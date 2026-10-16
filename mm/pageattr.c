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

DEFINE_LOCK_GUARD_0(cpa_pgtable, cpa_pgtable_lock(), cpa_pgtable_unlock())

static int should_split_large_page(struct cpa_data *cpa, struct cpa_leaf *leaf)
{
	unsigned long address = leaf->address;
	pte_t *kpte = leaf->kpte;

	if (cpa->req & CPA_REQ_SPLIT)
		return 1;

	guard(cpa_pgtable)();

	if (!_lookup_address_cpa(cpa, address, leaf) || leaf->kpte != kpte)
		return 1;

	return __should_split_large_page(cpa, leaf);
}

static int split_large_page(struct cpa_data *cpa, struct cpa_leaf *leaf)
{
	unsigned long address = leaf->address;
	pte_t *kpte = leaf->kpte;
	int ret = 1;
	pte_t *pte;

	spin_unlock(&cpa_lock);
	if (cpa->state & CPA_ST_MM_LOCKED)
		mmap_read_unlock(&init_mm);
	pte = pte_alloc_one_kernel(&init_mm);
	if (cpa->state & CPA_ST_MM_LOCKED)
		mmap_read_lock(&init_mm);
	spin_lock(&cpa_lock);
	if (!pte)
		return -ENOMEM;

	scoped_guard(cpa_pgtable) {
		if (_lookup_address_cpa(cpa, address, leaf) && leaf->kpte == kpte)
			ret = __split_large_page(cpa, leaf, pte);
	}

	if (ret)
		pte_free_kernel(&init_mm, pte);

	return 0;
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
	unsigned long address = __cpa_addr(cpa, cpa->curpage);
	struct cpa_leaf leaf;
	int split_res;

	for (;;) {
		if (!_lookup_address_cpa(cpa, address, &leaf) || pte_none(leaf.pte))
			return __cpa_process_fault(cpa, address);

		if (leaf.level == PGTABLE_LEVEL_PTE)
			break;

		/* Update large page or split it */
		split_res = cpa_handle_large_page(cpa, &leaf);
		if (split_res <= 0)
			return split_res;
	}

	__change_pte(cpa, &leaf);
	return 0;
}

/*
 * Does this page have an alias that the change has to be applied to as well?
 * Not if the caller asked otherwise, and not if this walk is itself already
 * updating an alias.
 */
static inline bool cpa_needs_alias(struct cpa_data *cpa)
{
	if (cpa->state & CPA_ST_ALIAS || cpa->req & CPA_REQ_NO_ALIAS)
		return false;

	return __cpa_needs_alias(__cpa_addr(cpa, cpa->curpage), cpa->pfn);
}

/*
 * Apply the change described by @cpa to its alias at @addr, except for the
 * protections in @keep.
 */
int cpa_change_alias(struct cpa_data *cpa, unsigned long addr, pgprot_t keep)
{
	struct cpa_data alias_cpa = *cpa;
	int ret;

	alias_cpa.vaddr = &addr;
	alias_cpa.req &= ~CPA_REQ_PAGES_ARRAY;
	alias_cpa.state |= CPA_ST_ALIAS;
	alias_cpa.state &= ~CPA_ST_FLUSHTLB;
	alias_cpa.curpage = 0;
	pgprot_val(alias_cpa.mask_set) &= ~pgprot_val(keep);
	pgprot_val(alias_cpa.mask_clr) &= ~pgprot_val(keep);

	ret = __change_page_attr_set_clr(&alias_cpa);

	/* The alias is outside of the range being changed */
	if (alias_cpa.state & CPA_ST_FLUSHTLB)
		cpa->state |= CPA_ST_FLUSHTLB_ALL;

	return ret;
}

int __change_page_attr_set_clr(struct cpa_data *cpa)
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

		if (cpa_needs_alias(cpa)) {
			ret = cpa_process_alias(cpa);
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
			collapsed += collapse_large_pages(__cpa_addr(cpa, i),
							  &pgtables);
	} else {
		addr = __cpa_addr(cpa, 0);
		start = addr & PMD_MASK;
		end = addr + PAGE_SIZE * cpa->numpages;

		for (addr = start; addr < end; addr += PMD_SIZE)
			collapsed += collapse_large_pages(addr, &pgtables);
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

int change_page_attr_set_clr(unsigned long *addr, int numpages,
			     pgprot_t mask_set, pgprot_t mask_clr,
			     unsigned int request, struct page **pages)
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
	cpa.req = request;
	cpa.curpage = 0;

	/* Avoid race with concurrent CPA collapse. */
	cpa.state |= CPA_ST_MM_LOCKED;
	scoped_guard(mmap_read_lock, &init_mm)
		ret = __change_page_attr_set_clr(&cpa);
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

	cpa_flush(&cpa);

	if (!ret && (cpa.req & CPA_REQ_COLLAPSE))
		cpa_collapse_large_pages(&cpa);

	return ret;
}

static int cpa_change_memory(unsigned long addr, int numpages, enum cpa_op op)
{
	const struct cpa_op_desc *desc = cpa_get_op_desc(op);

	if (!pgprot_val(desc->mask_set) && !pgprot_val(desc->mask_clr))
		return 0;

	return change_page_attr_set_clr(&addr, numpages, desc->mask_set,
					desc->mask_clr, desc->req, NULL);
}

int set_memory_x(unsigned long addr, int numpages)
{
	return cpa_change_memory(addr, numpages, CPA_SET_X);
}

int set_memory_nx(unsigned long addr, int numpages)
{
	return cpa_change_memory(addr, numpages, CPA_SET_NX);
}

int set_memory_ro(unsigned long addr, int numpages)
{
	return cpa_change_memory(addr, numpages, CPA_SET_RO);
}

int set_memory_rw(unsigned long addr, int numpages)
{
	return cpa_change_memory(addr, numpages, CPA_SET_RW);
}

#ifdef CONFIG_ARCH_HAS_SET_DIRECT_MAP
/*
 * Change the direct map without flushing the TLB or taking mmap_lock.
 * Splitting a large page allocates a page table and may sleep.
 */
static int cpa_change_direct_map(struct page *page, int numpages,
				 enum cpa_op op)
{
	unsigned long addr = (unsigned long)page_address(page);
	struct cpa_data cpa = {
		.vaddr = &addr,
		.numpages = numpages,
	};
	const struct cpa_op_desc *desc = cpa_get_op_desc(op);

	cpa.mask_set = desc->mask_set;
	cpa.mask_clr = desc->mask_clr;
	cpa.req = desc->req;

	return __change_page_attr_set_clr(&cpa);
}

int set_direct_map_invalid_noflush(struct page *page, unsigned int nr)
{
	return cpa_change_direct_map(page, nr, CPA_SET_INVALID);
}

int set_direct_map_default_noflush(struct page *page, unsigned int nr)
{
	return cpa_change_direct_map(page, nr, CPA_SET_DEFAULT);
}
#endif /* CONFIG_ARCH_HAS_SET_DIRECT_MAP */
