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
#include <linux/set_memory.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>

#include <asm/tlbflush.h>

#ifndef canon_pgprot
#define canon_pgprot(prot)	(prot)
#endif

#ifndef arch_cpa_aliases
static int arch_cpa_aliases(struct cpa_data *cpa, unsigned long vaddr,
			    struct cpa_alias *aliases)
{
	return 0;
}
#endif

#ifndef arch_cpa_flush
static void arch_cpa_flush(struct cpa_data *cpa, int err)
{
	unsigned long start;

	if (err || cpa->state & CPA_ST_FLUSHTLB_ALL ||
	    cpa->req & (CPA_REQ_ARRAY | CPA_REQ_PAGES_ARRAY)) {
		flush_tlb_all();
		return;
	}

	start = __cpa_addr(cpa, 0);
	flush_tlb_kernel_range(start, start + cpa->numpages * PAGE_SIZE);
}
#endif

#ifndef arch_cpa_collapse
static void arch_cpa_collapse(struct cpa_data *cpa)
{
}
#endif

/*
 * Serialize cpa() using cpa_lock so that we don't allow any other cpu, with
 * stale large tlb entries, to change the page attribute in parallel to some
 * other cpu splitting a large page entry along with changing the attribute.
 */
static DEFINE_SPINLOCK(cpa_lock);

/* Drop the CPA locks, e.g. to allocate memory, and take them again */
void cpa_unlock(struct cpa_data *cpa)
{
	spin_unlock(&cpa_lock);
	if (cpa->state & CPA_ST_MM_LOCKED)
		mmap_read_unlock(&init_mm);
}

void cpa_relock(struct cpa_data *cpa)
{
	if (cpa->state & CPA_ST_MM_LOCKED)
		mmap_read_lock(&init_mm);
	spin_lock(&cpa_lock);
}

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

static inline bool cpa_needs_alias(struct cpa_data *cpa)
{
	return !(cpa->state & CPA_ST_ALIAS || cpa->req & CPA_REQ_NO_ALIAS);
}

static int cpa_process_alias(struct cpa_data *cpa)
{
	unsigned long vaddr = __cpa_addr(cpa, cpa->curpage);
	struct cpa_alias aliases[CPA_MAX_ALIASES];
	int i, nr, ret;

	nr = arch_cpa_aliases(cpa, vaddr, aliases);

	for (i = 0; i < nr; i++) {
		struct cpa_data alias_cpa = *cpa;

		alias_cpa.vaddr = &aliases[i].addr;
		alias_cpa.req &= ~(CPA_REQ_PAGES_ARRAY | CPA_REQ_ARRAY);
		alias_cpa.state |= CPA_ST_ALIAS;
		alias_cpa.curpage = 0;
		pgprot_val(alias_cpa.mask_set) &= ~pgprot_val(aliases[i].keep);
		pgprot_val(alias_cpa.mask_clr) &= ~pgprot_val(aliases[i].keep);

		cpa->state |= CPA_ST_FLUSHTLB_ALL;

		ret = __change_page_attr_set_clr(&alias_cpa);
		cpa->state |= alias_cpa.state & CPA_ST_FLUSHTLB;
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
			ret = arch_change_page_attr(cpa);
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
	/*
	 * Take the mmap write lock on init_mm to:
	 * - Avoid a use-after-free if raced by ptdump (which takes its own
	 *   write lock on init_mm).
	 * - Serialise concurrent CPA walkers.
	 */
	guard(mmap_write_lock)(&init_mm);
	guard(spinlock)(&cpa_lock);

	arch_cpa_collapse(cpa);
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
	if (!(cpa.state & CPA_ST_FLUSHTLB))
		return ret;

	arch_cpa_flush(&cpa, ret);

	if (!ret && (cpa.req & CPA_REQ_COLLAPSE))
		cpa_collapse_large_pages(&cpa);

	return ret;
}

static int cpa_change_memory(unsigned long addr, int numpages, enum cpa_op op)
{
	struct cpa_op_desc desc;
	int ret;

	ret = arch_cpa_op_desc(op, &desc);
	if (ret)
		return ret;

	return change_page_attr_set_clr(&addr, numpages, desc.mask_set,
					desc.mask_clr, desc.req, NULL);
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
	struct cpa_op_desc desc;
	int ret;

	ret = arch_cpa_op_desc(op, &desc);
	if (ret)
		return ret;

	cpa.mask_set = desc.mask_set;
	cpa.mask_clr = desc.mask_clr;
	cpa.req = desc.req;

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
