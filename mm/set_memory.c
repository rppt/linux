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

static int should_split_large_page(pte_t *kpte, unsigned long address,
				   struct cpa_data *cpa)
{
	int do_split;

	if (cpa->force_split)
		return 1;

	spin_lock(&pgd_lock);
	do_split = arch_should_split_large_page(kpte, address, cpa);
	spin_unlock(&pgd_lock);

	return do_split;
}

static int split_large_page(struct cpa_data *cpa, pte_t *kpte,
			    unsigned long address)
{
	struct ptdesc *ptdesc;

	spin_unlock(&cpa_lock);
	ptdesc = pagetable_alloc(GFP_KERNEL, 0);
	spin_lock(&cpa_lock);
	if (!ptdesc)
		return -ENOMEM;

	if (arch_split_large_page(cpa, kpte, address, ptdesc))
		pagetable_free(ptdesc);

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
