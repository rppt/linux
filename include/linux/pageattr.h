/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGEATTR_H
#define _LINUX_PAGEATTR_H

#include <linux/bits.h>
#include <linux/pgtable.h>
#include <linux/types.h>

/* Caller-requested behavior, stored in cpa_data.req. */
#define CPA_REQ_ARRAY		BIT(0) /* cpa->vaddr is an array of addresses */
#define CPA_REQ_PAGES_ARRAY	BIT(1) /* cpa->pages is an array of pages */
#define CPA_REQ_NO_ALIAS	BIT(2) /* do not check aliases */
#define CPA_REQ_COLLAPSE	BIT(3) /* try to collapse large pages */
#define CPA_REQ_SPLIT		BIT(4) /* split large pages unconditionally */
#define CPA_REQ_ARCH(n)		BIT(16 + (n)) /* architecture specific */

/* Internally maintained state, stored in cpa_data.state. */
#define CPA_ST_FLUSHTLB		BIT(0) /* flush the TLB for changed pages */
#define CPA_ST_FLUSHTLB_ALL	BIT(1) /* flush all TLBs */
#define CPA_ST_MM_LOCKED	BIT(2) /* mmap read lock on init_mm */
#define CPA_ST_ALIAS		BIT(3) /* updating an alias */
#define CPA_ST_ARCH(n)		BIT(16 + (n)) /* architecture specific */

enum cpa_op {
	CPA_SET_RO,
	CPA_SET_RW,
	CPA_SET_X,
	CPA_SET_NX,
	CPA_SET_DEFAULT,
	CPA_SET_INVALID,
};

/* An alias of the range being changed that has to be changed as well. */
struct cpa_alias {
	unsigned long addr;
	pgprot_t keep;		/* protections not to change in the alias */
	bool ignore_err;
};

#define CPA_MAX_ALIASES	2

/* The protection changes and the request flags that implement a cpa_op. */
struct cpa_op_desc {
	pgprot_t mask_set;
	pgprot_t mask_clr;
	unsigned int req;
};

#include <asm/pageattr.h>

/*
 * The current flushing context - we pass it instead of 5 arguments:
 */
struct cpa_data {
	unsigned long	*vaddr;
	pgprot_t	mask_set;
	pgprot_t	mask_clr;
	unsigned long	numpages;
	unsigned long	curpage;
	unsigned long	pfn;
	unsigned int	state;
	unsigned int	req;
	struct page	**pages;
	struct arch_cpa_data arch;
};

int arch_cpa_op_desc(enum cpa_op op, struct cpa_op_desc *desc);
int arch_change_page_attr(struct cpa_data *cpa);

unsigned long __cpa_addr(struct cpa_data *cpa, unsigned long idx);
void cpa_unlock(struct cpa_data *cpa);
void cpa_relock(struct cpa_data *cpa);
int __change_page_attr_set_clr(struct cpa_data *cpa);
int change_page_attr_set_clr(unsigned long *addr, int numpages,
			     pgprot_t mask_set, pgprot_t mask_clr,
			     unsigned int request, struct page **pages);

#endif /* _LINUX_PAGEATTR_H */
