// SPDX-License-Identifier: GPL-2.0-only

#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/pgtable.h>

#include <linux/set_memory.h>

/*
 * Serialize cpa() so that we don't allow any other cpu, with stale large tlb
 * entries, to change the page attribute in parallel to some other cpu
 * splitting a large page entry along with changing the attribute.
 */
static DEFINE_SPINLOCK(cpa_lock);

static struct cpa_arch_info *cpa_arch_info;

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

/*
 * Lookup the page table entry for a virtual address in a specific pgd.
 * Return a pointer to the entry (or NULL if the entry does not exist),
 * the level of the entry, and the effective NX and RW bits of all
 * page table levels.
 */
pte_t *lookup_address_in_pgd_attr(pgd_t *pgd, unsigned long address,
				  unsigned int *level,
				  bool *ret_nx, bool *ret_rw)
{
	unsigned long rw = _PAGE_RW;
	unsigned int exec = 1;
	pte_t *pte = NULL;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	*level = PGTABLE_LEVEL_PGD;
	if (pgd_none(*pgd))
		goto out;

	*level = PGTABLE_LEVEL_P4D;
	exec &= pgd_exec(*pgd);
	rw &= pgd_write(*pgd);

	p4d = p4d_offset(pgd, address);
	if (p4d_none(*p4d))
		goto out;

	if (p4d_leaf(*p4d) || !p4d_present(*p4d)) {
		pte = (pte_t *)p4d;
		goto out;
	}

	*level = PGTABLE_LEVEL_PUD;
	exec &= p4d_exec(*p4d);
	rw &= p4d_write(*p4d);

	pud = pud_offset(p4d, address);
	if (pud_none(*pud))
		goto out;

	if (pud_leaf(*pud) || !pud_present(*pud)) {
		pte = (pte_t *)pud;
		goto out;
	}

	*level = PGTABLE_LEVEL_PMD;
	exec &= pud_exec(*pud);
	rw &= pud_write(*pud);

	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
		goto out;

	if (pmd_leaf(*pmd) || !pmd_present(*pmd)) {
		pte = (pte_t *)pmd;
		goto out;
	}

	*level = PGTABLE_LEVEL_PTE;
	exec &= pmd_exec(*pmd);
	rw &= pmd_write(*pmd);
	pte = pte_offset_kernel(pmd, address);

out:
	*ret_nx = !exec;
	*ret_rw = !!rw;

	return pte;
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

	spin_unlock(&cpa_lock);
	ptdesc = pagetable_alloc(GFP_KERNEL, 0);
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
		arch_change_pte(cpa, address, kpte, old_pte, nx, rw);
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
	 * return. cpa->numpages and cpa->tlbflush have been updated in
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

		spin_lock(&cpa_lock);
		ret = __change_page_attr(cpa, primary);
		spin_unlock(&cpa_lock);
		if (ret)
			goto out;

		if (primary && !(cpa->flags & CPA_NO_CHECK_ALIAS) &&
		    cpa_should_update_alias(cpa_addr(cpa, cpa->curpage), cpa->pfn)) {
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
