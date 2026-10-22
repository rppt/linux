/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGEATTR_H
#define _LINUX_PAGEATTR_H

#include <linux/bits.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/types.h>

#include <asm/tlbflush.h>

/* Caller-requested behavior, stored in cpa_data.req. */
#define CPA_REQ_PAGES_ARRAY	BIT(0) /* cpa->pages is an array of pages */
#define CPA_REQ_NO_ALIAS	BIT(1) /* do not check aliases */
#define CPA_REQ_COLLAPSE	BIT(2) /* try to collapse large pages */
#define CPA_REQ_SPLIT		BIT(3) /* split large pages unconditionally */

/* Internally maintained state, stored in cpa_data.state. */
#define CPA_ST_FLUSHTLB		BIT(0) /* flush the TLB for changed pages */
#define CPA_ST_FLUSHTLB_ALL	BIT(1) /* flush all TLBs */
#define CPA_ST_MM_LOCKED	BIT(2) /* mmap read lock on init_mm */
#define CPA_ST_ALIAS		BIT(3) /* updating an alias */
#define CPA_ST_STATIC_PROT	BIT(4) /* enforce static protections on split */
#define CPA_ST_LAZY_MMU		BIT(5) /* in the lazy MMU mode */

#include <asm/pageattr.h>

/*
 * The current flushing context - we pass it instead of 5 arguments:
 */
struct cpa_data {
	unsigned long	vaddr;
	pgd_t		*pgd;
	pgprot_t	mask_set;
	pgprot_t	mask_clr;
	unsigned long	numpages;
	unsigned long	curpage;
	unsigned long	pfn;
	unsigned int	state;
	unsigned int	req;
	struct page	**pages;
};

/* A leaf entry in the kernel page tables that maps an address. */
struct cpa_leaf {
	unsigned long address;
	unsigned long psize;
	unsigned long pfn;
	pte_t *kpte;
	pte_t pte;
	pgprot_t prot;
	enum pgtable_level level;
	bool nx;
	bool rw;
};

pte_t *arch_cpa_lookup_leaf(struct cpa_data *cpa, unsigned long address,
			    struct cpa_leaf *leaf);
int arch_cpa_should_split_large_page(struct cpa_data *cpa, struct cpa_leaf *leaf);
int arch_cpa_split_large_page(struct cpa_data *cpa, struct cpa_leaf *leaf,
			      pte_t *pbase);
int arch_cpa_process_fault(struct cpa_data *cpa, unsigned long vaddr);
void arch_cpa_change_pte(struct cpa_data *cpa, struct cpa_leaf *leaf);

static inline pgprot_t cpa_new_prot(struct cpa_data *cpa, pgprot_t prot)
{
	pgprot_val(prot) &= ~pgprot_val(cpa->mask_clr);
	pgprot_val(prot) |= pgprot_val(cpa->mask_set);

	return prot;
}

static inline unsigned long cpa_addr(struct cpa_data *cpa, unsigned long idx)
{
	if (cpa->req & CPA_REQ_PAGES_ARRAY) {
		struct page *page = cpa->pages[idx];

		if (unlikely(PageHighMem(page)))
			return 0;

		return (unsigned long)page_address(page);
	}

	return cpa->vaddr + idx * PAGE_SIZE;
}

#ifndef canon_pgprot
#define canon_pgprot(prot)	(prot)
#endif

#ifndef arch_cpa_pgtable_lock
static inline void arch_cpa_pgtable_lock(void)
{
}
#endif

#ifndef arch_cpa_pgtable_unlock
static inline void arch_cpa_pgtable_unlock(void)
{
}
#endif

#ifndef arch_cpa_process_alias
static inline int arch_cpa_process_alias(struct cpa_data *cpa)
{
	return 0;
}
#endif

#ifndef arch_cpa_flush
static inline void arch_cpa_flush(struct cpa_data *cpa)
{
	unsigned long start;

	if (cpa->state & CPA_ST_FLUSHTLB_ALL ||
	    cpa->req & CPA_REQ_PAGES_ARRAY) {
		flush_tlb_all();
		return;
	}

	start = cpa_addr(cpa, 0);
	flush_tlb_kernel_range(start, start + cpa->numpages * PAGE_SIZE);
}
#endif

/*
 * Whether the CPA code should batch the page table updates in the lazy MMU
 * mode. Reading an entry back right after updating it is only safe when the
 * lazy MMU mode does not defer the updates themselves.
 */
#ifndef arch_cpa_lazy_mmu
static inline bool arch_cpa_lazy_mmu(void)
{
	return false;
}
#endif

#ifndef arch_cpa_collapse
static inline int arch_cpa_collapse(unsigned long addr,
				    struct list_head *pgtables)
{
	return 0;
}
#endif

int __cpa_set_clr(struct cpa_data *cpa);
int cpa_change_alias(struct cpa_data *cpa, unsigned long addr, pgprot_t keep);
int cpa_set_clr(unsigned long addr, int numpages, pgprot_t mask_set,
		pgprot_t mask_clr, unsigned int request, struct page **pages);
int cpa_change_direct_map(struct page *page, int numpages,
			  pgprot_t mask_set, pgprot_t mask_clr);

static inline int change_page_attr_set(unsigned long addr, int numpages,
				       pgprot_t mask)
{
	return cpa_set_clr(addr, numpages, mask, __pgprot(0), 0, NULL);
}

static inline int change_page_attr_clear(unsigned long addr, int numpages,
					 pgprot_t mask)
{
	return cpa_set_clr(addr, numpages, __pgprot(0), mask, 0, NULL);
}

#endif /* _LINUX_PAGEATTR_H */
