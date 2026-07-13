// SPDX-License-Identifier: GPL-2.0-only

#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/pgtable.h>

#include <linux/set_memory.h>

static struct cpa_arch_info *cpa_arch_info;

static DEFINE_SPINLOCK(cpa_lock);

static inline bool cpa_lock_required(void)
{
	return !cpa_arch_info->no_cpa_lock && !debug_pagealloc_enabled();
}

static inline void arch_lock(void)
{
	if (cpa_arch_info->lock)
		spin_lock(cpa_arch_info->lock);
}

static inline void arch_unlock(void)
{
	if (cpa_arch_info->lock)
		spin_unlock(cpa_arch_info->lock);
}

/*
 * Lookup the page table entry for a virtual address in a specific pgd.
 * Return a pointer to the entry (or NULL if the entry does not exist),
 * the level of the entry, and the effective NX and RW bits of all
 * page table levels.
 */
pte_t *lookup_address_in_pgd_attr(pgd_t *pgd, unsigned long address,
				  unsigned int *level, bool *nx, bool *rw)
{
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	*level = PGTABLE_LEVEL_PGD;
	*nx = false;
	*rw = true;

	if (pgd_none(*pgd))
		return NULL;

	*level = PGTABLE_LEVEL_P4D;
	*nx |= pgtable_entry_nx(pgd_val(*pgd));
	*rw &= pgtable_entry_rw(pgd_val(*pgd));

	p4d = p4d_offset(pgd, address);
	if (p4d_none(*p4d))
		return NULL;

	if (p4d_leaf(*p4d) || !p4d_present(*p4d))
		return (pte_t *)p4d;

	*level = PGTABLE_LEVEL_PUD;
	*nx |= pgtable_entry_nx(p4d_val(*p4d));
	*rw &= pgtable_entry_rw(p4d_val(*p4d));

	pud = pud_offset(p4d, address);
	if (pud_none(*pud))
		return NULL;

	if (pud_leaf(*pud) || !pud_present(*pud))
		return (pte_t *)pud;

	*level = PGTABLE_LEVEL_PMD;
	*nx |= pgtable_entry_nx(pud_val(*pud));
	*rw &= pgtable_entry_rw(pud_val(*pud));

	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
		return NULL;

	if (pmd_leaf(*pmd) || !pmd_present(*pmd))
		return (pte_t *)pmd;

	*level = PGTABLE_LEVEL_PTE;
	*nx |= pgtable_entry_nx(pmd_val(*pmd));
	*rw &= pgtable_entry_rw(pmd_val(*pmd));

	return pte_offset_kernel(pmd, address);
}

/*
 * Lookup the page table entry for a virtual address in a specific pgd.
 * Return a pointer to the entry and the level of the mapping.
 */
pte_t *lookup_address_in_pgd(pgd_t *pgd, unsigned long address,
			     unsigned int *level)
{
	bool nx, rw;

	return lookup_address_in_pgd_attr(pgd, address, level, &nx, &rw);
}

/*
 * Lookup the page table entry for a virtual address. Return a pointer
 * to the entry and the level of the mapping.
 *
 * Note: the function returns p4d, pud or pmd either when the entry is marked
 * large or when the present bit is not set. Otherwise it returns NULL.
 */
pte_t *lookup_address(unsigned long address, unsigned int *level)
{
	return lookup_address_in_pgd(pgd_offset_k(address), address, level);
}
EXPORT_SYMBOL_GPL(lookup_address);

static pte_t *_lookup_address_cpa(struct cpa_data *cpa, unsigned long address,
				  unsigned int *level, bool *nx, bool *rw)
{
	pgd_t *pgd;

	if (!cpa->pgd)
		pgd = pgd_offset_k(address);
	else
		pgd = cpa->pgd + pgd_index(address);

	return lookup_address_in_pgd_attr(pgd, address, level, nx, rw);
}

unsigned long cpa_addr(struct cpa_data *cpa, unsigned long idx)
{
	if (cpa->flags & CPA_PAGES_ARRAY) {
		struct page *page = cpa->pages[idx];

		if (unlikely(PageHighMem(page)))
			return 0;

		return (unsigned long)page_address(page);
	}

	if (cpa->flags & CPA_ARRAY)
		return cpa->vaddr[idx];

	return *cpa->vaddr + idx * PAGE_SIZE;
}

static bool overlaps(unsigned long r1_start, unsigned long r1_end,
		     unsigned long r2_start, unsigned long r2_end)
{
	return (r1_start <= r2_end && r1_end >= r2_start) ||
		(r2_start <= r1_end && r2_end >= r1_start);
}

/*
 * Certain areas of memory require very specific protection flags, for example
 * kernel text must stay executable and .rodata read-only. Callers don't always
 * get this right, so strip the architecture's forbidden bits from any leaf that
 * overlaps a protected zone (see struct cpa_prot_zone). Architectures without
 * such zones (nr_prot_zones == 0) get their protection returned unchanged.
 */
static __always_inline pgprot_t __apply_static_protections(pgprot_t prot,
		unsigned long start, unsigned long pfn, unsigned long npg,
		unsigned long lpsize)
{
	const struct cpa_arch_info *ai = cpa_arch_info;
	unsigned long end = start + npg * PAGE_SIZE - 1;
	u64 forbidden = 0;
	unsigned int i;

	if (!ai->nr_prot_zones)
		return prot;

	/*
	 * There is no point in checking conflicts when the requested mapping is
	 * setting the leaf !PRESENT.
	 */
	if (ai->present_mask && !((u64)pgprot_val(prot) & ai->present_mask))
		return prot;

	for (i = 0; i < ai->nr_prot_zones; i++) {
		const struct cpa_prot_zone *z = &ai->prot_zones[i];
		unsigned long s = z->pfn_based ? pfn : start;
		unsigned long e = z->pfn_based ? pfn + npg - 1 : end;

		if (z->enable && !*z->enable)
			continue;
		/*
		 * Some zones only apply when the change does not span a full
		 * large page (e.g. preserve large kernel-text mappings).
		 */
		if (z->lp_partial_only &&
		    lpsize == npg * PAGE_SIZE && !(start & (lpsize - 1)))
			continue;
		if (!overlaps(s, e, z->start, z->end))
			continue;
		/*
		 * Some zones only forbid bits when the current mapping is a
		 * large page (splitting it would lose the protection anyway).
		 */
		if (z->needs_lp_check) {
			unsigned int level;

			if (!lookup_address(start, &level) ||
			    level == PGTABLE_LEVEL_PTE)
				continue;
		}
		forbidden |= z->forbidden;
	}

	return __pgprot(pgprot_val(prot) & ~forbidden);
}

pgprot_t apply_static_protections(pgprot_t prot, unsigned long start,
				  unsigned long pfn, unsigned long npg,
				  unsigned long lpsize)
{
	return __apply_static_protections(prot, start, pfn, npg, lpsize);
}

static int should_split_large_page(pte_t *kpte, unsigned long address,
				   struct cpa_data *cpa)
{
	unsigned int level;
	int do_split;
	bool nx, rw;
	pte_t *tmp;

	if (cpa->force_split)
		return 1;

	arch_lock();
	/*
	 * Check for races, another CPU might have split this page
	 * up already:
	 */
	tmp = _lookup_address_cpa(cpa, address, &level, &nx, &rw);
	if (tmp != kpte) {
		arch_unlock();
		return 1;
	}

	do_split = arch_should_split_large_page(kpte, address, cpa, level,
						nx, rw);

	arch_unlock();
	return do_split;
}

static int split_large_page(struct cpa_data *cpa, pte_t *kpte,
			    unsigned long address)
{
	struct ptdesc *ptdesc;
	unsigned int level;
	bool nx, rw;
	pte_t *tmp;

	if (cpa_lock_required())
		spin_unlock(&cpa_lock);
	ptdesc = pagetable_alloc(GFP_KERNEL, 0);
	if (cpa_lock_required())
		spin_lock(&cpa_lock);
	if (!ptdesc)
		return -ENOMEM;

	arch_lock();

	/*
	 * Check for races, another CPU might have split this page
	 * up for us already:
	 */
	tmp = _lookup_address_cpa(cpa, address, &level, &nx, &rw);
	if (tmp != kpte) {
		pagetable_free(ptdesc);
		arch_unlock();
		return 0;
	}

	if (arch_split_large_page(cpa, kpte, address, level, ptdesc))
		pagetable_free(ptdesc);

	arch_unlock();
	return 0;
}

static int __change_page_attr(struct cpa_data *cpa, int primary)
{
	unsigned long address;
	int do_split, err;
	unsigned int level;
	pte_t *kpte, old_pte;
	bool nx, rw;

	address = cpa_addr(cpa, cpa->curpage);
repeat:
	kpte = _lookup_address_cpa(cpa, address, &level, &nx, &rw);
	if (!kpte)
		return arch_cpa_process_fault(cpa, address, primary);

	old_pte = *kpte;
	if (pte_none(old_pte))
		return arch_cpa_process_fault(cpa, address, primary);

	if (level == PGTABLE_LEVEL_PTE) {
		pgprot_t old_prot = pte_pgprot(old_pte);
		unsigned long pfn = pte_pfn(old_pte);
		pgprot_t new_prot;
		pte_t new_pte;

		new_prot = cpa_pgprot_apply_masks(old_prot, cpa->mask_clr,
						  cpa->mask_set);
		/* Hand in lpsize = 0 to enforce the protection mechanism */
		new_prot = __apply_static_protections(new_prot, address, pfn,
						      1, 0);
		new_prot = verify_rwx(old_prot, new_prot, address, pfn, 1,
				      nx, rw);
		new_prot = cpa_pgprot_fixup(new_prot);

		/*
		 * Keep the pfn from the existing PTE, we are only changing its
		 * attributes.
		 */
		new_pte = pfn_pte(pfn, new_prot);
		cpa->pfn = pfn;
		if (pte_val(old_pte) != pte_val(new_pte)) {
			cpa_set_pte(kpte, new_pte);
			cpa->flags |= CPA_FLUSHTLB;
		}
		cpa->numpages = 1;
		return 0;
	}

	/*
	 * Check, whether we can keep the large page intact
	 * and just change the pte:
	 */
	do_split = should_split_large_page(kpte, address, cpa);
	/*
	 * When the range fits into the existing large page,
	 * return. cp->numpages and cpa->tlbflush have been updated in
	 * try_large_page:
	 */
	if (do_split <= 0)
		return do_split;

	/*
	 * We have to split the large page:
	 */
	err = split_large_page(cpa, kpte, address);
	if (!err)
		goto repeat;

	return err;
}

int __change_page_attr_set_clr(struct cpa_data *cpa, int primary)
{
	unsigned long numpages = cpa->numpages;
	unsigned long rempages = numpages;
	int ret = 0;

	/*
	 * No changes, easy!
	 */
	if (!(pgprot_val(cpa->mask_set) | pgprot_val(cpa->mask_clr)) &&
	    !cpa->force_split)
		return ret;

	while (rempages) {
		/*
		 * Store the remaining nr of pages for the large page
		 * preservation check.
		 */
		cpa->numpages = rempages;
		/* for array changes, we can't use large page */
		if (cpa->flags & (CPA_ARRAY | CPA_PAGES_ARRAY))
			cpa->numpages = 1;

		if (cpa_lock_required())
			spin_lock(&cpa_lock);
		ret = __change_page_attr(cpa, primary);
		if (cpa_lock_required())
			spin_unlock(&cpa_lock);
		if (ret)
			goto out;

		if (primary && !(cpa->flags & CPA_NO_CHECK_ALIAS)) {
			ret = arch_cpa_process_alias(cpa);
			if (ret)
				goto out;
		}

		/*
		 * Adjust the number of pages with the result of the
		 * CPA operation. Either a large page has been
		 * preserved or a single page update happened.
		 */
		BUG_ON(cpa->numpages > rempages || !cpa->numpages);
		rempages -= cpa->numpages;
		cpa->curpage += cpa->numpages;
	}

out:
	/* Restore the original numpages */
	cpa->numpages = numpages;
	return ret;
}

int change_page_attr_set_clr(unsigned long *addr, int numpages,
			     pgprot_t mask_set, pgprot_t mask_clr,
			     int force_split, int in_flag,
			     struct page **pages)
{
	struct cpa_data cpa;
	int err;

	memset(&cpa, 0, sizeof(cpa));

	/*
	 * Check, if we are requested to set a not supported
	 * feature.  Clearing non-supported features is OK.
	 */
	mask_set = canon_pgprot(mask_set);

	if (!pgprot_val(mask_set) && !pgprot_val(mask_clr) && !force_split)
		return 0;

	/* Ensure we are PAGE_SIZE aligned */
	if (in_flag & CPA_ARRAY) {
		int i;
		for (i = 0; i < numpages; i++) {
			if (addr[i] & ~PAGE_MASK) {
				addr[i] &= PAGE_MASK;
				WARN_ON_ONCE(1);
			}
		}
	} else if (!(in_flag & CPA_PAGES_ARRAY)) {
		/*
		 * in_flag of CPA_PAGES_ARRAY implies it is aligned.
		 * No need to check in that case
		 */
		if (*addr & ~PAGE_MASK) {
			*addr &= PAGE_MASK;
			/*
			 * People should not be passing in unaligned addresses:
			 */
			WARN_ON_ONCE(1);
		}
	}

	/* Must avoid aliasing mappings in the highmem code */
	kmap_flush_unused();

	vm_unmap_aliases();

	cpa.vaddr = addr;
	cpa.pages = pages;
	cpa.numpages = numpages;
	cpa.mask_set = mask_set;
	cpa.mask_clr = mask_clr;
	cpa.flags = in_flag;
	cpa.curpage = 0;
	cpa.force_split = force_split;

	err = __change_page_attr_set_clr(&cpa, 1);

	/*
	 * Check whether we really changed something:
	 */
	if (!(cpa.flags & CPA_FLUSHTLB))
		goto out;

	arch_cpa_flush(&cpa, err);

out:
	return err;
}

void __init cpa_init(void)
{
	cpa_arch_info = cpa_arch_setup();
}
