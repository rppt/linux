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

static unsigned long __cpa_addr(struct cpa_data *cpa, unsigned long idx)
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

static int should_split_large_page(struct cpa_data *cpa,
				   struct cpa_split_data *sd)
{
	unsigned long numpages, lpaddr;

	if (cpa->force_split)
		return 1;

	sd->psize = pgtable_level_size(sd->kpte, sd->level);
	sd->pmask = pgtable_level_mask(sd->kpte, sd->level);

	/*
	 * Calculate the number of pages, which fit into this large
	 * page starting at address:
	 */
	lpaddr = (sd->address + sd->psize) & sd->pmask;
	numpages = (lpaddr - sd->address) >> PAGE_SHIFT;
	if (numpages < cpa->numpages)
		cpa->numpages = numpages;

	return arch_should_split_large_page(cpa, sd);
}

static int change_large_page_attr(struct cpa_data *cpa, pte_t *kpte,
				  unsigned long address)
{
	struct cpa_split_data sd = {
		.kpte = kpte,
		.address = address,
	};
	pte_t *tmp;
	int do_split = 1;

	/*
	 * Preallocate the page table for a potential split before taking the
	 * pgd_lock.  pagetable_alloc() may sleep, so cpa_lock is dropped for
	 * the allocation and retaken before the lookup, keeping the whole
	 * keep-or-split sequence under a single, stable lookup.
	 */
	spin_unlock(&cpa_lock);
	sd.ptdesc = pagetable_alloc(GFP_KERNEL, 0);
	spin_lock(&cpa_lock);
	if (!sd.ptdesc)
		return -ENOMEM;

	spin_lock(&pgd_lock);

	/*
	 * Re-check under the lock: another CPU might have split this page up
	 * already.  A single lookup serves both the keep-or-split decision and
	 * the split itself, which now share one lock acquisition.
	 */
	tmp = _lookup_address_cpa(cpa, address, &sd.level, &sd.nx, &sd.rw);
	if (tmp != kpte)
		goto out_free_ptdesc;

	do_split = should_split_large_page(cpa, &sd);
	if (do_split <= 0)
		goto out_free_ptdesc;

	/*
	 * Split the large page.  On success the preallocated page table is
	 * installed in the page tables and must not be freed.
	 */
	if (arch_split_large_page(cpa, &sd) == 0)
		goto out_unlock;

out_free_ptdesc:
	pagetable_free(sd.ptdesc);
out_unlock:
	spin_unlock(&pgd_lock);

	return do_split;
}

static int __change_page_attr(struct cpa_data *cpa, int primary)
{
	unsigned long address;
	int ret;
	unsigned int level;
	pte_t *kpte, old_pte;
	bool nx, rw;

	address = __cpa_addr(cpa, cpa->curpage);
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
	 * The address maps a large page. Try to keep it, otherwise split it
	 * up and retry on the freshly installed smaller mapping.
	 */
	ret = change_large_page_attr(cpa, kpte, address);
	if (ret == 1)
		goto repeat;

	return ret;
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
		    cpa_should_update_alias(__cpa_addr(cpa, cpa->curpage), cpa->pfn)) {
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
