/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_PAGEATTR_H
#define _LINUX_PAGEATTR_H

#include <linux/errno.h>
#include <linux/mm_types.h>
#include <linux/pgtable.h>

/* Request flags */
#define CPA_NOFLUSH	BIT(0)	/* the caller flushes the TLB, a hint */
#define CPA_NO_ALIAS	BIT(1)	/* don't change aliases of the range */
/*
 * Don't sleep and don't take locks; the caller guarantees there are no
 * concurrent requests.
 */
#define CPA_ATOMIC	BIT(2)
#define CPA_SPLIT	BIT(3)	/* only split leaves larger than PAGE_SIZE */

/* What a request changed, set by the core */
#define CPA_CHANGED_PROT	BIT(0)	/* leaves in the range */
#define CPA_CHANGED_SPLIT	BIT(1)	/* leaves were split */
#define CPA_CHANGED_ALIAS	BIT(2)	/* leaves in the aliases */

/**
 * enum cpa_prot - operations of the generic set_memory() APIs
 * @CPA_PROT_RO: make read-only
 * @CPA_PROT_RW: make writable
 * @CPA_PROT_X: make executable
 * @CPA_PROT_NX: make non-executable
 * @CPA_PROT_NP: make not present
 * @CPA_PROT_P: make present
 * @CPA_PROT_INVALID: make a direct map range invalid
 * @CPA_PROT_DEFAULT: restore the default protections of a direct map range
 * @CPA_PROT_NR: number of operations
 */
enum cpa_prot {
	CPA_PROT_RO,
	CPA_PROT_RW,
	CPA_PROT_X,
	CPA_PROT_NX,
	CPA_PROT_NP,
	CPA_PROT_P,
#ifdef CONFIG_ARCH_HAS_SET_DIRECT_MAP
	CPA_PROT_INVALID,
	CPA_PROT_DEFAULT,
#endif
	CPA_PROT_NR,
};

/**
 * struct cpa_prot_op - protections changed by a set_memory() operation
 * @set: protection bits to set
 * @clr: protection bits to clear
 * @alias: change the aliases of the range as well
 *
 * CPA_PROT_DEFAULT must restore the permissions of PAGE_KERNEL.
 */
struct cpa_prot_op {
	pgprot_t set;
	pgprot_t clr;
	bool alias;
};

/**
 * struct cpa_req - a request to change kernel page table permissions
 * @addr: page aligned start of the virtual address range
 * @numpages: number of pages in the range
 * @set: protection bits to set
 * @clr: protection bits to clear
 * @alias_set: protection bits to set in the aliases of the range
 * @alias_clr: protection bits to clear in the aliases of the range
 * @flags: CPA_* request flags
 * @changed: CPA_CHANGED_* flags, set by the core
 * @fail_split: fail the Nth split of the request, for the tests
 *
 * Aliases are the direct map addresses of the pages mapped by the range.
 * They are changed only if @alias_set or @alias_clr are not empty.
 */
struct cpa_req {
	unsigned long addr;
	unsigned long numpages;
	pgprot_t set;
	pgprot_t clr;
	pgprot_t alias_set;
	pgprot_t alias_clr;
	unsigned int flags;
	unsigned int changed;
#ifdef CONFIG_PAGEATTR_KUNIT_TEST
	unsigned int fail_split;
#endif
};

/**
 * struct cpa_range - a virtual address range changed by a request
 * @start: start of the range
 * @end: end of the range
 * @set: protection bits to set
 * @clr: protection bits to clear
 * @alias: the range is an alias of a part of the request
 */
struct cpa_range {
	unsigned long start;
	unsigned long end;
	pgprot_t set;
	pgprot_t clr;
	bool alias;
};

/**
 * struct cpa_leaf - a leaf entry of the kernel page tables
 * @level: page table level of the entry
 * @entry: pointer to the first entry of the leaf
 * @start: first virtual address mapped by the leaf
 * @size: size of the range mapped by the leaf
 * @nr: number of entries in the leaf, larger than one for contiguous groups
 * @pfn: pfn mapped at @start
 * @prot: protections of the leaf, in the format of a PTE
 *
 * @prot does not include the bits that depend on the level of the entry
 * or on being a part of a contiguous group, so that leaves of different
 * levels with the same permissions have the same @prot.
 */
struct cpa_leaf {
	enum pgtable_level level;
	void *entry;
	unsigned long start;
	unsigned long size;
	unsigned int nr;
	unsigned long pfn;
	pgprot_t prot;
};

extern struct cpa_prot_op arch_cpa_prot_ops[CPA_PROT_NR];

int cpa_change(struct cpa_req *req);
void cpa_req_add_op(struct cpa_req *req, enum cpa_prot op);
void *cpa_alloc_table(struct cpa_req *req, enum pgtable_level level,
		      unsigned long addr);
void cpa_free_table(enum pgtable_level level, void *table);
void cpa_flush_ranges(struct cpa_req *req);

#ifdef CONFIG_GENERIC_PAGEATTR
#include <asm/pageattr.h>
#endif

/*
 * Mandatory architecture hooks.
 */

/**
 * arch_cpa_read_leaf - decode a page table entry
 * @leaf: leaf with @level and @entry set and @nr set to one
 *
 * The core calls this for entries that are not none at every level below
 * PGD. Leaf entries must be recognized regardless of whether they are
 * present.
 *
 * Set @pfn and @prot from the entry pointed to by @leaf->entry and @nr to
 * the number of entries in the contiguous group that contains it.
 * @pfn is the pfn of that entry rather than of the first entry of the group.
 *
 * Return: true if the entry is a leaf, false if it points to a table.
 */
bool arch_cpa_read_leaf(struct cpa_leaf *leaf);

/**
 * arch_cpa_write_leaf - change the protections of a leaf
 * @req: the request
 * @leaf: the leaf to change
 * @prot: new protections, in the format of a PTE
 *
 * Write all @leaf->nr entries of @leaf without TLB maintenance, it is done
 * by arch_cpa_flush().
 */
void arch_cpa_write_leaf(struct cpa_req *req, struct cpa_leaf *leaf,
			 pgprot_t prot);

/**
 * arch_cpa_flush - perform TLB maintenance after a request
 * @req: the request
 *
 * Called once for every request with non-empty @req->changed, including
 * failed requests. CPA_NOFLUSH means that the caller will flush the TLB
 * for the range of @req, the architecture decides if that is enough.
 * cpa_flush_ranges() is a helper that flushes the changed ranges.
 */
void arch_cpa_flush(struct cpa_req *req);

/*
 * Optional architecture hooks.
 */

#ifndef arch_cpa_check
/**
 * arch_cpa_check - check if a request may change its range
 * @req: the request
 *
 * Return: 0 if the range of @req can be changed or a negative error code.
 */
static inline int arch_cpa_check(struct cpa_req *req)
{
	return 0;
}
#endif

#ifndef arch_cpa_new_prot
/**
 * arch_cpa_new_prot - calculate the new protections for a part of a leaf
 * @req: the request
 * @range: the range that contains @leaf
 * @leaf: the leaf
 * @start: start of the part of @leaf covered by the request
 * @end: end of the part of @leaf covered by the request
 * @prot: the new protections
 *
 * Must return the same result when called again for the same leaf.
 *
 * Return: false if the new protections are not the same for the whole
 * [@start, @end) range.
 */
static inline bool arch_cpa_new_prot(struct cpa_req *req,
				     struct cpa_range *range,
				     struct cpa_leaf *leaf,
				     unsigned long start, unsigned long end,
				     pgprot_t *prot)
{
	*prot = __pgprot((pgprot_val(leaf->prot) & ~pgprot_val(range->clr)) |
			 pgprot_val(range->set));
	return true;
}
#endif

#ifndef arch_cpa_split
/**
 * arch_cpa_split - split a leaf
 * @req: the request
 * @leaf: the leaf
 *
 * Replace a contiguous group (@leaf->nr > 1) with single entries of the
 * same level, or a single entry with a table of the next level, that map
 * the same pfns with the same attributes. Perform any TLB maintenance the
 * architecture requires to change the size of a mapping.
 * cpa_alloc_table() and cpa_free_table() allocate and free the tables.
 *
 * Return: 0 on success or a negative error code.
 */
static inline int arch_cpa_split(struct cpa_req *req, struct cpa_leaf *leaf)
{
	return -EOPNOTSUPP;
}
#endif

#ifdef CONFIG_ARCH_HAS_DIRECT_MAP_COUNT
void direct_map_count(enum pgtable_level level, long nr);
#else
static inline void direct_map_count(enum pgtable_level level, long nr) { }
#endif

#ifndef arch_direct_map_levels
/*
 * arch_direct_map_levels - mask of the levels the direct map may use,
 * one DirectMap line per level in /proc/meminfo
 */
#ifdef __PAGETABLE_PUD_FOLDED
#define arch_direct_map_levels()					\
	(BIT(PGTABLE_LEVEL_PTE) | BIT(PGTABLE_LEVEL_PMD))
#else
#define arch_direct_map_levels()					\
	(BIT(PGTABLE_LEVEL_PTE) | BIT(PGTABLE_LEVEL_PMD) |		\
	 BIT(PGTABLE_LEVEL_PUD))
#endif
#endif

#ifndef arch_direct_map_cont
/*
 * arch_direct_map_cont - number of the direct map entries at @level that are
 * parts of contiguous groups, @size is set to the size of a group or to 0 if
 * the level has no contiguous groups
 */
static inline unsigned long arch_direct_map_cont(enum pgtable_level level,
						 unsigned long *size)
{
	*size = 0;
	return 0;
}
#endif

#endif /* _LINUX_PAGEATTR_H */
