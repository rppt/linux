// SPDX-License-Identifier: GPL-2.0-only
/*
 * Change the attributes of kernel page table mappings.
 *
 * Based on arch/x86/mm/pat/set_memory.c, which grew this machinery over the
 * years:
 *
 * Copyright 2002 Andi Kleen, SuSE Labs.
 * Thanks to Ben LaHaise for precious feedback.
 */

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
DEFINE_SPINLOCK(cpa_lock);

unsigned long __cpa_addr(struct cpa_data *cpa, unsigned long idx)
{
	if (cpa->req & CPA_REQ_PAGES_ARRAY) {
		struct page *page = cpa->pages[idx];

		if (unlikely(PageHighMem(page)))
			return 0;

		return (unsigned long)page_address(page);
	}

	if (cpa->req & CPA_REQ_ARRAY)
		return cpa->vaddr[idx];

	return *cpa->vaddr + idx * PAGE_SIZE;
}

/*
 * Lookup the page table entry for a virtual address in a specific pgd.
 * Return a pointer to the entry and the level of the mapping.
 */
pte_t *lookup_address_in_pgd(pgd_t *pgd, unsigned long address,
			     enum pgtable_level *level)
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
pte_t *lookup_address(unsigned long address, enum pgtable_level *level)
{
	return lookup_address_in_pgd(pgd_offset_k(address), address, level);
}
EXPORT_SYMBOL_GPL(lookup_address);

static pte_t *_lookup_address_cpa(struct cpa_data *cpa, unsigned long address,
				  enum pgtable_level *level, bool *nx, bool *rw)
{
	pgd_t *pgd;

	if (!cpa->pgd)
		pgd = pgd_offset_k(address);
	else
		pgd = cpa->pgd + pgd_index(address);

	return lookup_address_in_pgd_attr(pgd, address, level, nx, rw);
}

static pte_t *cpa_lookup_leaf(struct cpa_data *cpa, struct cpa_leaf *leaf,
			      unsigned long address)
{
	enum pgtable_level level;

	leaf->kpte = _lookup_address_cpa(cpa, address, &level, &leaf->nx,
					 &leaf->rw);
	if (!leaf->kpte)
		return NULL;

	leaf->address = address;
	leaf->level = level;
	leaf->psize = pgtable_level_size(level);
	leaf->pte = *leaf->kpte;

	return leaf->kpte;
}

static int should_split_large_page(struct cpa_data *cpa, struct cpa_leaf *leaf)
{
	unsigned long address = leaf->address;
	pte_t *kpte = leaf->kpte;

	if (cpa->req & CPA_REQ_SPLIT)
		return 1;

	guard(spinlock)(&pgd_lock);

	if (!cpa_lookup_leaf(cpa, leaf, address) || leaf->kpte != kpte)
		return 1;

	return arch_should_split_large_page(cpa, leaf);
}

static int split_large_page(struct cpa_data *cpa, struct cpa_leaf *leaf)
{
	unsigned long address = leaf->address;
	pte_t *kpte = leaf->kpte;
	pte_t *pte;
	int ret;

	spin_unlock(&cpa_lock);
	if (cpa->state & CPA_ST_MM_LOCKED)
		mmap_read_unlock(&init_mm);
	pte = pte_alloc_one_kernel(&init_mm);
	if (cpa->state & CPA_ST_MM_LOCKED)
		mmap_read_lock(&init_mm);
	spin_lock(&cpa_lock);
	if (!pte)
		return -ENOMEM;

	scoped_guard(spinlock, &pgd_lock) {
		if (!cpa_lookup_leaf(cpa, leaf, address) || leaf->kpte != kpte)
			ret = 1;
		else
			ret = arch_split_large_page(cpa, leaf, pte);
	}

	if (ret)
		pte_free_kernel(&init_mm, pte);

	return 0;
}

static int cpa_handle_large_page(struct cpa_data *cpa, struct cpa_leaf *leaf)
{
	unsigned long pmask = pgtable_level_mask(leaf->level);
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
		if (!cpa_lookup_leaf(cpa, &leaf, address) || pte_none(leaf.pte))
			return arch_cpa_process_fault(cpa, address);

		if (leaf.level == PGTABLE_LEVEL_PTE)
			break;

		/* Update large page or split it */
		split_res = cpa_handle_large_page(cpa, &leaf);
		if (split_res <= 0)
			return split_res;
	}

	arch_change_pte(cpa, &leaf);
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

	return arch_cpa_needs_alias(__cpa_addr(cpa, cpa->curpage), cpa->pfn);
}

/*
 * Apply a change that was made at one address to every alias of the same
 * page.
 */
static int cpa_process_alias(struct cpa_data *cpa)
{
	struct cpa_alias aliases[CPA_MAX_ALIASES];
	unsigned long vaddr = __cpa_addr(cpa, cpa->curpage);
	int i, n, ret;

	n = arch_cpa_aliases(cpa, vaddr, aliases);

	for (i = 0; i < n; i++) {
		struct cpa_data alias_cpa = *cpa;

		alias_cpa.vaddr = &aliases[i].addr;
		alias_cpa.req &= ~(CPA_REQ_PAGES_ARRAY | CPA_REQ_ARRAY);
		alias_cpa.state |= CPA_ST_ALIAS;
		alias_cpa.curpage = 0;

		pgprot_val(alias_cpa.mask_set) &= ~pgprot_val(aliases[i].keep);
		pgprot_val(alias_cpa.mask_clr) &= ~pgprot_val(aliases[i].keep);

		cpa->state |= CPA_ST_FLUSHTLB_ALL;

		ret = __change_page_attr_set_clr(&alias_cpa);
		if (ret && !aliases[i].ignore_err)
			return ret;
	}

	return 0;
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
		if (cpa->req & (CPA_REQ_ARRAY | CPA_REQ_PAGES_ARRAY))
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
	if (request & CPA_REQ_ARRAY) {
		int i;
		for (i = 0; i < numpages; i++) {
			if (addr[i] & ~PAGE_MASK) {
				addr[i] &= PAGE_MASK;
				WARN_ON_ONCE(1);
			}
		}
	} else if (!(request & CPA_REQ_PAGES_ARRAY)) {
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
	if (cpa.state & CPA_ST_FLUSHTLB)
		arch_cpa_flush(&cpa, ret);

	return ret;
}

static int cpa_change_memory(unsigned long addr, int numpages, enum cpa_op op)
{
	struct cpa_op_desc desc = arch_cpa_op_descs[op];

	arch_cpa_prepare(&desc);

	return change_page_attr_set_clr(&addr, numpages, desc.mask_set,
					desc.mask_clr, desc.req, NULL);
}

int set_memory_ro(unsigned long addr, int numpages)
{
	return cpa_change_memory(addr, numpages, CPA_SET_RO);
}

int set_memory_rw(unsigned long addr, int numpages)
{
	return cpa_change_memory(addr, numpages, CPA_SET_RW);
}

int set_memory_x(unsigned long addr, int numpages)
{
	return cpa_change_memory(addr, numpages, CPA_SET_X);
}

int set_memory_nx(unsigned long addr, int numpages)
{
	return cpa_change_memory(addr, numpages, CPA_SET_NX);
}

static int cpa_change_direct_map(struct page *page, int numpages,
				 enum cpa_op op)
{
	unsigned long addr = (unsigned long)page_address(page);
	struct cpa_op_desc desc = arch_cpa_op_descs[op];
	struct cpa_data cpa = { .vaddr = &addr,
				.pgd = NULL,
				.numpages = numpages };

	arch_cpa_prepare(&desc);

	cpa.mask_set = desc.mask_set;
	cpa.mask_clr = desc.mask_clr;
	cpa.req = desc.req;

	/*
	 * No alias checking needed for the direct map. otherwise,
	 * we may need to break large pages for 64-bit kernel text
	 * mappings (this adds to complexity if we want to do this from
	 * atomic context especially). Let's keep it simple!
	 */
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
