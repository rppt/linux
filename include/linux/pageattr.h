/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGEATTR_H
#define _LINUX_PAGEATTR_H

/*
 * Interface between the generic change_page_attr() implementation in
 * mm/set_memory.c and the architecture hooks it calls out to.
 *
 * This is not a consumer API. Callers of set_memory_*() and
 * set_direct_map_*() include <linux/set_memory.h> instead.
 */

#include <linux/bits.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>
#include <linux/spinlock.h>
#include <linux/types.h>

struct page;

enum cpa_op {
	CPA_SET_RO,
	CPA_SET_RW,
	CPA_SET_X,
	CPA_SET_NX,
	CPA_SET_DEFAULT,
	CPA_SET_INVALID,
	CPA_OP_NUM,
};

struct cpa_op_desc {
	pgprot_t mask_set;
	pgprot_t mask_clr;
	unsigned int flags;
	bool supported;
};

#define CPA_OP_DESC(_set, _clr, _flags)		\
	{					\
		.mask_set = __pgprot(_set),	\
		.mask_clr = __pgprot(_clr),	\
		.flags = (_flags),		\
		.supported = true,		\
	}

extern const struct cpa_op_desc arch_cpa_op_descs[CPA_OP_NUM];

/*
 * Architectures that keep aliases of the primary mapping override this to
 * skip the alias walk when the primary update is enough.
 */
#ifndef arch_cpa_should_update_alias
#define arch_cpa_should_update_alias(vaddr, pfn)	true
#endif

/* Caller-requested behavior, stored in cpa_data.req. */
#define CPA_REQ_ARRAY		BIT(0) /* cpa->vaddr is an array of addresses */
#define CPA_REQ_PAGES_ARRAY	BIT(1) /* cpa->pages is an array of pages */
#define CPA_REQ_NO_ALIAS	BIT(2) /* do not check aliases */
#define CPA_REQ_COLLAPSE	BIT(3) /* try to collapse large pages */
#define CPA_REQ_SPLIT		BIT(4) /* split large pages unconditionally */

/* Internally maintained state, stored in cpa_data.state. */
#define CPA_ST_FLUSHTLB		BIT(0) /* flush the TLB for changed pages */
#define CPA_ST_FLUSHTLB_ALL	BIT(1) /* flush all TLBs */
#define CPA_ST_MM_LOCKED	BIT(2) /* mmap read lock on init_mm */
#define CPA_ST_STATIC_PROT	BIT(3) /* enforce static protections */
#define CPA_ST_ALIAS		BIT(4) /* updating an alias */

extern spinlock_t cpa_lock;

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

struct cpa_split_data {
	unsigned long	address;
	unsigned long	psize;
	unsigned long	pmask;
	pte_t		*kpte;
	pte_t		*pbase;
	enum pgtable_level level;
	bool		nx;
	bool		rw;
};

unsigned long cpa_addr(struct cpa_data *cpa, unsigned long idx);
pte_t *lookup_address_in_pgd_attr(pgd_t *pgd, unsigned long address,
				  unsigned int *level, bool *nx, bool *rw);
int cpa_revalidate_mapping(struct cpa_data *cpa, struct cpa_split_data *sd);
int cpa_prepare_split(struct cpa_data *cpa, struct cpa_split_data *sd);

int arch_cpa_process_fault(struct cpa_data *cpa, unsigned long vaddr);
int arch_cpa_process_alias(struct cpa_data *cpa);
int arch_should_split_large_page(struct cpa_data *cpa,
				 struct cpa_split_data *sd);
/* A zero return consumes sd->pbase; nonzero leaves it for the caller to free. */
int arch_split_large_page(struct cpa_data *cpa, struct cpa_split_data *sd);
void arch_change_pte(struct cpa_data *cpa, unsigned long address,
		     pte_t *kpte, pte_t old_pte, bool nx, bool rw);
/*
 * arch_cpa_prepare() runs immediately before the page tables are walked and
 * may adjust the masks or start a batched update. It is paired with
 * arch_cpa_finish() for set_memory() and with arch_cpa_finish_direct_map()
 * for set_direct_map(), both of which run unconditionally once the walk is
 * over.
 */
int arch_cpa_prepare(struct cpa_data *cpa);
void arch_cpa_finish(struct cpa_data *cpa, int err);
void arch_cpa_finish_direct_map(struct cpa_data *cpa);

int __change_page_attr_set_clr(struct cpa_data *cpa);
int change_page_attr_set_clr(unsigned long *addr, int numpages,
			     pgprot_t mask_set, pgprot_t mask_clr,
			     unsigned int request,
			     struct page **pages);

static inline int change_page_attr_set(unsigned long *addr, int numpages,
				       pgprot_t mask, int array)
{
	return change_page_attr_set_clr(addr, numpages, mask, __pgprot(0),
		(array ? CPA_REQ_ARRAY : 0), NULL);
}

static inline int change_page_attr_clear(unsigned long *addr, int numpages,
					 pgprot_t mask, int array)
{
	return change_page_attr_set_clr(addr, numpages, __pgprot(0), mask,
		(array ? CPA_REQ_ARRAY : 0), NULL);
}

#endif /* _LINUX_PAGEATTR_H */
