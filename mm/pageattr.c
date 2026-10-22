// SPDX-License-Identifier: GPL-2.0-only
/*
 * Changes of the kernel page table attributes.
 *
 * Copyright 2002 Andi Kleen, SuSE Labs.
 */
#include <linux/cleanup.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>
#include <linux/pageattr.h>
#include <linux/pgalloc.h>
#include <linux/set_memory.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>

/*
 * Serialize cpa() using cpa_lock so that we don't allow any other cpu, with
 * stale large tlb entries, to change the page attribute in parallel to some
 * other cpu splitting a large page entry along with changing the attribute.
 */
static DEFINE_SPINLOCK(cpa_lock);

DEFINE_LOCK_GUARD_0(cpa_pgtable, arch_cpa_pgtable_lock(),
		    arch_cpa_pgtable_unlock())

/* Look up the leaf again and check it is still the same large leaf */
static bool cpa_revalidate_leaf(struct cpa_data *cpa, struct cpa_leaf *leaf)
{
	unsigned long psize = leaf->psize;
	pte_t *kpte = leaf->kpte;

	return arch_cpa_lookup_leaf(cpa, leaf->address, leaf) &&
	       leaf->kpte == kpte && leaf->psize == psize;
}

static int should_split_large_page(struct cpa_data *cpa, struct cpa_leaf *leaf)
{
	guard(cpa_pgtable)();

	if (!cpa_revalidate_leaf(cpa, leaf))
		return CPA_SPLIT_RETRY;

	return arch_cpa_should_split_large_page(cpa, leaf);
}

static int split_large_page(struct cpa_data *cpa, struct cpa_leaf *leaf)
{
	int ret = 1;
	pte_t *pte;

	spin_unlock(&cpa_lock);
	if (cpa->state & CPA_ST_LAZY_MMU)
		lazy_mmu_mode_pause();
	if (cpa->state & CPA_ST_MM_LOCKED)
		mmap_read_unlock(&init_mm);
	pte = pte_alloc_one_kernel(&init_mm);
	if (cpa->state & CPA_ST_MM_LOCKED)
		mmap_read_lock(&init_mm);
	if (cpa->state & CPA_ST_LAZY_MMU)
		lazy_mmu_mode_resume();
	spin_lock(&cpa_lock);
	if (!pte)
		return -ENOMEM;

	scoped_guard(cpa_pgtable) {
		if (cpa_revalidate_leaf(cpa, leaf))
			ret = arch_cpa_split_large_page(cpa, leaf, pte);
	}

	if (ret)
		pte_free_kernel(&init_mm, pte);

	return ret < 0 ? ret : 0;
}

static int cpa_handle_large_page(struct cpa_data *cpa, struct cpa_leaf *leaf)
{
	unsigned long pmask = ~(leaf->psize - 1);
	unsigned long psize = leaf->psize;
	int do_split, err;

	/*
	 * Check, whether we can keep the large page intact
	 * and just change the pte:
	 */
	do_split = should_split_large_page(cpa, leaf);
	if (do_split < 0)
		return do_split;
	if (do_split == CPA_SPLIT_RETRY)
		return 1;

	/*
	 * When the range fits into the existing large page, no split is
	 * required.
	 */
	if (!do_split) {
		unsigned long offset = (leaf->address & ~pmask) >> PAGE_SHIFT;
		unsigned long numpages = psize >> PAGE_SHIFT;

		cpa->numpages = min(cpa->numpages, numpages - offset);
		cpa->pfn = leaf->pfn + offset;
		return 0;
	}

	/*
	 * We have to split the large page:
	 */
	err = split_large_page(cpa, leaf);
	if (err)
		return err;

	return do_split;
}

static int __change_page_attr(struct cpa_data *cpa)
{
	unsigned long address = cpa_addr(cpa, cpa->curpage);
	struct cpa_leaf leaf;
	int split_res;

	for (;;) {
		if (!arch_cpa_lookup_leaf(cpa, address, &leaf) || pte_none(leaf.pte))
			return arch_cpa_process_fault(cpa, address);

		if (leaf.psize == PAGE_SIZE)
			break;

		/* Update large page or split it */
		split_res = cpa_handle_large_page(cpa, &leaf);
		if (split_res <= 0)
			return split_res;
	}

	arch_cpa_change_pte(cpa, &leaf);
	return 0;
}

/*
 * Apply the change described by @cpa to its alias at @addr, except for the
 * protections in @keep.
 */
int cpa_change_alias(struct cpa_data *cpa, unsigned long addr, pgprot_t keep)
{
	struct cpa_data alias_cpa = *cpa;
	int ret;

	alias_cpa.vaddr = addr;
	alias_cpa.req &= ~CPA_REQ_PAGES_ARRAY;
	alias_cpa.state |= CPA_ST_ALIAS;
	alias_cpa.state &= ~(CPA_ST_FLUSHTLB | CPA_ST_FLUSHTLB_ALL);
	alias_cpa.curpage = 0;
	pgprot_val(alias_cpa.mask_set) &= ~pgprot_val(keep);
	pgprot_val(alias_cpa.mask_clr) &= ~pgprot_val(keep);

	ret = __cpa_set_clr(&alias_cpa);

	/* The alias is outside of the range being changed */
	if (alias_cpa.state & (CPA_ST_FLUSHTLB | CPA_ST_FLUSHTLB_ALL))
		cpa->state |= CPA_ST_FLUSHTLB_ALL;

	return ret;
}

int __cpa_set_clr(struct cpa_data *cpa)
{
	unsigned long numpages = cpa->numpages;
	unsigned long rempages = numpages;
	int ret = 0;

	/*
	 * No changes, easy!
	 */
	if (!(pgprot_val(cpa->mask_set) | pgprot_val(cpa->mask_clr)) &&
	    !(cpa->req & CPA_REQ_SPLIT))
		return ret;

	if (arch_cpa_lazy_mmu()) {
		cpa->state |= CPA_ST_LAZY_MMU;
		lazy_mmu_mode_enable();
	}

	while (rempages) {
		/*
		 * Store the remaining nr of pages for the large page
		 * preservation check.
		 */
		cpa->numpages = rempages;
		/* for array changes, we can't use large page */
		if (cpa->req & CPA_REQ_PAGES_ARRAY)
			cpa->numpages = 1;

		scoped_guard(spinlock, &cpa_lock)
			ret = __change_page_attr(cpa);
		if (ret)
			goto out;

		if (!(cpa->state & CPA_ST_ALIAS) &&
		    !(cpa->req & CPA_REQ_NO_ALIAS)) {
			ret = arch_cpa_process_alias(cpa);
			if (ret)
				goto out;
		}

		/*
		 * Adjust the number of pages with the result of the
		 * CPA operation. Either a large page has been
		 * preserved or a single page update happened.
		 */
		if (WARN_ON_ONCE(cpa->numpages > rempages || !cpa->numpages)) {
			ret = -EINVAL;
			goto out;
		}
		rempages -= cpa->numpages;
		cpa->curpage += cpa->numpages;
	}

out:
	if (cpa->state & CPA_ST_LAZY_MMU) {
		lazy_mmu_mode_disable();
		cpa->state &= ~CPA_ST_LAZY_MMU;
	}

	/* Restore the original numpages */
	cpa->numpages = numpages;
	return ret;
}

static void cpa_collapse_large_pages(struct cpa_data *cpa)
{
	unsigned long start, addr, end;
	struct ptdesc *ptdesc, *tmp;
	LIST_HEAD(pgtables);
	int collapsed = 0;
	int i;

	/*
	 * Take the mmap write lock on init_mm to:
	 * - Avoid a use-after-free if raced by ptdump (which takes its own
	 *   write lock on init_mm).
	 * - Serialise concurrent CPA walkers.
	 */
	guard(mmap_write_lock)(&init_mm);
	guard(spinlock)(&cpa_lock);

	if (cpa->req & CPA_REQ_PAGES_ARRAY) {
		for (i = 0; i < cpa->numpages; i++)
			collapsed += arch_cpa_collapse(cpa_addr(cpa, i),
						       &pgtables);
	} else {
		addr = cpa_addr(cpa, 0);
		start = addr & PMD_MASK;
		end = addr + PAGE_SIZE * cpa->numpages;

		for (addr = start; addr < end; addr += PMD_SIZE)
			collapsed += arch_cpa_collapse(addr, &pgtables);
	}

	if (!collapsed)
		return;

	flush_tlb_all();

	list_for_each_entry_safe(ptdesc, tmp, &pgtables, pt_list) {
		list_del(&ptdesc->pt_list);
		/*
		 * Only early alloc'd direct map should not be flagged PG_table
		 * here and those shouldn't be collapsed. However be abundantly
		 * cautious and handle the !PG_table case too.
		 */
		if (PageTable((ptdesc_page(ptdesc))))
			pagetable_dtor_free(ptdesc);
		else
			pagetable_free(ptdesc);
	}
}

int cpa_set_clr(unsigned long addr, int numpages, pgprot_t mask_set,
		pgprot_t mask_clr, unsigned int request, struct page **pages)
{
	struct cpa_data cpa;
	int ret;

	memset(&cpa, 0, sizeof(cpa));

	/*
	 * Check, if we are requested to set a not supported
	 * feature.  Clearing non-supported features is OK.
	 */
	mask_set = canon_pgprot(mask_set);

	if (!pgprot_val(mask_set) && !pgprot_val(mask_clr) &&
	    !(request & CPA_REQ_SPLIT))
		return 0;

	/* Ensure we are PAGE_SIZE aligned */
	if (!(request & CPA_REQ_PAGES_ARRAY)) {
		/*
		 * CPA_REQ_PAGES_ARRAY implies it is aligned.
		 * No need to check in that case
		 */
		if (addr & ~PAGE_MASK) {
			addr &= PAGE_MASK;
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
	cpa.req = request;
	cpa.curpage = 0;

	/* Avoid race with concurrent CPA collapse. */
	cpa.state |= CPA_ST_MM_LOCKED;
	scoped_guard(mmap_read_lock, &init_mm)
		ret = __cpa_set_clr(&cpa);
	cpa.state &= ~CPA_ST_MM_LOCKED;

	/*
	 * Check whether we really changed something:
	 */
	if (!(cpa.state & (CPA_ST_FLUSHTLB | CPA_ST_FLUSHTLB_ALL)))
		return ret;

	/*
	 * On error; flush everything to be sure.
	 */
	if (ret)
		cpa.state |= CPA_ST_FLUSHTLB_ALL;

	arch_cpa_flush(&cpa);

	if (!ret && (cpa.req & CPA_REQ_COLLAPSE))
		cpa_collapse_large_pages(&cpa);

	return ret;
}

/*
 * Change the direct map without flushing the TLB or taking mmap_lock.
 * Splitting a large page allocates a page table and may sleep.
 *
 * No alias checking needed for the direct map updates. Otherwise, we may need
 * to break large pages for 64-bit kernel text mappings (this adds to
 * complexity if we want to do this from atomic context especially). Let's
 * keep it simple!
 */
int cpa_change_direct_map(struct page *page, int numpages,
			  pgprot_t mask_set, pgprot_t mask_clr)
{
	unsigned long addr = (unsigned long)page_address(page);
	struct cpa_data cpa = {
		.vaddr = addr,
		.numpages = numpages,
		.mask_set = mask_set,
		.mask_clr = mask_clr,
		.req = CPA_REQ_NO_ALIAS,
	};

	return __cpa_set_clr(&cpa);
}
