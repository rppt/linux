/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_PAGEATTR_H
#define _LINUX_PAGEATTR_H

#include <linux/pgtable.h>
#include <linux/set_memory.h>
#include <linux/spinlock.h>
#include <linux/types.h>

/*
 * The change a set_memory() call requests.  An architecture describes each
 * operation it supports with a cpa_op_desc entry and leaves out the ones it
 * cannot implement.
 */
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
	pgprot_t	mask_set;
	pgprot_t	mask_clr;
	unsigned int	req;
};

#define CPA_OP_DESC(_set, _clr, _req)		\
	{					\
		.mask_set = __pgprot(_set),	\
		.mask_clr = __pgprot(_clr),	\
		.req = (_req),			\
	}

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

/*
 * The state of a change_page_attr() call, passed around instead of a handful
 * of arguments.
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

/*
 * An alias mapping of a page that a change has to be applied to as well.
 * @keep are the protection bits the alias owns and the change must not
 * touch.  @ignore_err marks an alias whose range is imprecise, so that a
 * failure to update it is not reported to the caller.
 */
struct cpa_alias {
	unsigned long	addr;
	pgprot_t	keep;
	bool		ignore_err;
};

#define CPA_MAX_ALIASES 2

/* The page table entry a walk landed on. */
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

/*
 * Serializes CPA against itself, so that a CPU cannot change an attribute
 * through a stale large TLB entry while another CPU is splitting it.
 */
extern spinlock_t cpa_lock;

/* The address the walk is at for page @idx of the request. */
unsigned long __cpa_addr(struct cpa_data *cpa, unsigned long idx);

/*
 * Walk the range described by @cpa and apply the change to every entry.
 * Does not flush anything; the caller is responsible for that.
 */
int __change_page_attr_set_clr(struct cpa_data *cpa);

/*
 * Change the attributes of @numpages pages starting at @addr, as described by
 * @mask_set, @mask_clr and @request.  The architecture entry points for the
 * changes that have an enum cpa_op are built on top of this.
 */
int change_page_attr_set_clr(unsigned long *addr, int numpages,
			     pgprot_t mask_set, pgprot_t mask_clr,
			     unsigned int request, struct page **pages);


/* The operations this architecture supports, indexed by enum cpa_op. */
extern const struct cpa_op_desc arch_cpa_op_descs[CPA_OP_NUM];

/*
 * Adjust a copy of an arch_cpa_op_descs[] entry for what this CPU actually
 * implements, before it is used for a walk.
 */
void arch_cpa_prepare(struct cpa_op_desc *desc);

/*
 * Try to apply the change described by @cpa to the large leaf the walk landed
 * on, as described by @leaf.  Returns 0 if the leaf was updated or needs no
 * update, 1 if it has to be split first, or a negative error.
 */
int arch_should_split_large_page(struct cpa_data *cpa, struct cpa_leaf *leaf);

/*
 * Replace the large leaf described by @leaf with a table of next level
 * entries in @pbase mapping the same memory with the same protections.
 * Returns 0 on success, 1 if the leaf is gone and @pbase was not consumed.
 */
int arch_split_large_page(struct cpa_data *cpa, struct cpa_leaf *leaf,
			      pte_t *pbase);

/*
 * Does the page at @vaddr have aliases that the change has to be applied to
 * as well?  Runs once per page, so architectures that have aliases should
 * answer inline.
 */
#ifndef arch_cpa_needs_alias
static inline bool arch_cpa_needs_alias(unsigned long vaddr,
					unsigned long pfn)
{
	return false;
}

static inline int arch_cpa_aliases(struct cpa_data *cpa, unsigned long vaddr,
				   struct cpa_alias *aliases)
{
	return 0;
}
#else
/*
 * Collect the aliases of the page at @vaddr that the change has to be applied
 * to as well, and return how many there are.  Only called when
 * arch_cpa_needs_alias() said there is at least one.
 */
int arch_cpa_aliases(struct cpa_data *cpa, unsigned long vaddr,
		     struct cpa_alias *aliases);
#endif

/*
 * The walk found no entry for @vaddr.  Returns 0 if that is expected, having
 * set cpa->numpages to the number of pages to skip, or a negative error.
 */
int arch_cpa_process_fault(struct cpa_data *cpa, unsigned long vaddr);

/*
 * Apply the change described by @cpa to the PTE the walk landed on, as
 * described by @leaf.  Updates cpa->pfn and cpa->numpages, and sets
 * CPA_ST_FLUSHTLB if the entry really changed.
 */
void arch_change_pte(struct cpa_data *cpa, struct cpa_leaf *leaf);

/*
 * Make the changes done by a change_page_attr() walk visible: flush the TLB,
 * and whatever else the architecture needs.  Called only when the walk
 * changed something, with @err set to what the walk returned.
 */
void arch_cpa_flush(struct cpa_data *cpa, int err);

#endif /* _LINUX_PAGEATTR_H */
