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

enum cpa_op {
	CPA_SET_RO,
	CPA_SET_RW,
	CPA_SET_X,
	CPA_SET_NX,
	CPA_SET_DEFAULT,
	CPA_SET_INVALID,
	CPA_OP_NUM,
};

/* The protection changes and the request flags that implement a cpa_op. */
struct cpa_op_desc {
	pgprot_t mask_set;
	pgprot_t mask_clr;
	unsigned int req;
};

#define CPA_OP_DESC(_set, _clr, _req)		\
	{					\
		.mask_set = __pgprot(_set),	\
		.mask_clr = __pgprot(_clr),	\
		.req = (_req),			\
	}

#include <asm/pageattr.h>

/*
 * The current flushing context - we pass it instead of 5 arguments:
 */
struct cpa_data {
	unsigned long	*vaddr;
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
	enum pgtable_level level;
	bool nx;
	bool rw;
};

const struct cpa_op_desc *arch_cpa_get_op_desc(enum cpa_op op);

pte_t *arch_cpa_lookup_leaf(struct cpa_data *cpa, unsigned long address,
			    struct cpa_leaf *leaf);
int arch_cpa_should_split_large_page(struct cpa_data *cpa, struct cpa_leaf *leaf);
int arch_cpa_split_large_page(struct cpa_data *cpa, struct cpa_leaf *leaf,
			      pte_t *pbase);
int arch_cpa_process_fault(struct cpa_data *cpa, unsigned long vaddr);
void arch_cpa_change_pte(struct cpa_data *cpa, struct cpa_leaf *leaf);

static inline unsigned long cpa_addr(struct cpa_data *cpa, unsigned long idx)
{
	if (cpa->req & CPA_REQ_PAGES_ARRAY) {
		struct page *page = cpa->pages[idx];

		if (unlikely(PageHighMem(page)))
			return 0;

		return (unsigned long)page_address(page);
	}

	return *cpa->vaddr + idx * PAGE_SIZE;
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

#ifndef arch_cpa_needs_alias
static inline bool arch_cpa_needs_alias(unsigned long vaddr, unsigned long pfn)
{
	return false;
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

#ifndef arch_cpa_collapse
static inline int arch_cpa_collapse(unsigned long addr,
				    struct list_head *pgtables)
{
	return 0;
}
#endif

int __cpa_set_clr(struct cpa_data *cpa);
int cpa_change_alias(struct cpa_data *cpa, unsigned long addr, pgprot_t keep);
int cpa_set_clr(unsigned long *addr, int numpages, pgprot_t mask_set,
		pgprot_t mask_clr, unsigned int request, struct page **pages);

#endif /* _LINUX_PAGEATTR_H */
