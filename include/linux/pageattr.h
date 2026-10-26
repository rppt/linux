/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_PAGEATTR_H
#define _LINUX_PAGEATTR_H

#include <linux/errno.h>
#include <linux/mm_types.h>
#include <linux/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>

/* Request flags */
#define CPA_NOFLUSH	BIT(0)	/* the caller flushes the TLB */
#define CPA_COLLAPSE	BIT(1)	/* collapse tables around the range */
#define CPA_NO_ALIAS	BIT(2)	/* don't change aliases of the range */
/*
 * Don't sleep and don't take locks; the caller guarantees there are no
 * concurrent requests. Tables are never collapsed.
 */
#define CPA_ATOMIC	BIT(3)
#define CPA_SPLIT	BIT(4)	/* split leaves larger than PAGE_SIZE */

/**
 * enum cpa_prot_op - operations of the generic set_memory() APIs
 * @CPA_PROT_RO: make read-only
 * @CPA_PROT_RW: make writable
 * @CPA_PROT_X: make executable
 * @CPA_PROT_NX: make non-executable
 * @CPA_PROT_NP: make not present
 * @CPA_PROT_P: make present
 * @CPA_PROT_INVALID: make a direct map range invalid
 * @CPA_PROT_DEFAULT: restore default protections of a direct map range
 */
enum cpa_prot_op {
	CPA_PROT_RO,
	CPA_PROT_RW,
	CPA_PROT_X,
	CPA_PROT_NX,
	CPA_PROT_NP,
	CPA_PROT_P,
	CPA_PROT_INVALID,
	CPA_PROT_DEFAULT,
};

/**
 * struct cpa_req - a request to change kernel page table permissions
 * @addr: page aligned start of the virtual address range
 * @numpages: number of pages in the range
 * @set: protection bits to set
 * @clr: protection bits to clear
 * @flags: CPA_* request flags
 * @pgd: page table to change, NULL for the kernel page table
 * @flush_start: start of the range that needs a TLB flush, set by the core
 * @flush_end: end of the range that needs a TLB flush, set by the core
 * @alias_flush_start: start of the aliases that need a TLB flush
 * @alias_flush_end: end of the aliases that need a TLB flush
 * @collapsed: last blocks checked for collapse at PMD and PUD levels
 *
 * A request either succeeds or fails before any permission is changed.
 * Tables of a page table other than the kernel page table are never
 * collapsed.
 */
struct cpa_req {
	unsigned long addr;
	unsigned long numpages;
	pgprot_t set;
	pgprot_t clr;
	unsigned int flags;
	pgd_t *pgd;

	unsigned long flush_start;
	unsigned long flush_end;
	unsigned long alias_flush_start;
	unsigned long alias_flush_end;
	unsigned long collapsed[2];
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

int cpa_change(struct cpa_req *req);
bool cpa_linear_alias(unsigned long addr, unsigned long pfn, unsigned long nr,
		      struct cpa_range *alias);

#ifdef CONFIG_GENERIC_PAGEATTR
void cpa_lock(void);
void cpa_unlock(void);
#else
static inline void cpa_lock(void) {}
static inline void cpa_unlock(void) {}
#endif

#ifdef CONFIG_GENERIC_PAGEATTR
#include <asm/pageattr.h>
#endif

/*
 * Mandatory architecture hooks.
 */

/**
 * arch_cpa_prot - get protections to change for a set_memory() operation
 * @op: the operation
 * @set: protection bits to set
 * @clr: protection bits to clear
 */
void arch_cpa_prot(enum cpa_prot_op op, pgprot_t *set, pgprot_t *clr);

/**
 * arch_cpa_read_leaf - decode a leaf entry
 * @leaf: leaf with @level and @entry set
 *
 * Set @pfn and @prot from the entry pointed to by @leaf->entry and @nr to
 * the number of entries in the contiguous group that contains it, or to one.
 * @pfn is the pfn of that entry rather than of the first entry of the group.
 */
void arch_cpa_read_leaf(struct cpa_leaf *leaf);

/**
 * arch_cpa_write_leaf - change the protections of a leaf
 * @req: the request
 * @leaf: the leaf to change
 * @prot: new protections, in the format of a PTE
 *
 * Write all @leaf->nr entries of @leaf. The TLB is flushed by the core
 * unless the request has CPA_NOFLUSH.
 */
void arch_cpa_write_leaf(struct cpa_req *req, struct cpa_leaf *leaf,
			 pgprot_t prot);

/*
 * Optional architecture hooks.
 */

#ifndef arch_cpa_check_range
/**
 * arch_cpa_check_range - check if a request may change its range
 * @req: the request
 *
 * Return: 0 if the range of @req can be changed or a negative error code.
 */
static inline int arch_cpa_check_range(struct cpa_req *req)
{
	return 0;
}
#endif

#ifndef arch_cpa_p4d_leaf
/**
 * arch_cpa_p4d_leaf - check if a P4D entry is a leaf
 * @p4d: the entry
 *
 * Return true for a leaf regardless of whether it is present.
 */
static inline bool arch_cpa_p4d_leaf(p4d_t p4d)
{
	return p4d_leaf(p4d);
}
#endif

#ifndef arch_cpa_pud_leaf
/**
 * arch_cpa_pud_leaf - check if a PUD entry is a leaf
 * @pud: the entry
 *
 * Return true for a leaf regardless of whether it is present.
 */
static inline bool arch_cpa_pud_leaf(pud_t pud)
{
	return pud_leaf(pud);
}
#endif

#ifndef arch_cpa_pmd_leaf
/**
 * arch_cpa_pmd_leaf - check if a PMD entry is a leaf
 * @pmd: the entry
 *
 * Return true for a leaf regardless of whether it is present.
 */
static inline bool arch_cpa_pmd_leaf(pmd_t pmd)
{
	return pmd_leaf(pmd);
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

#ifndef arch_cpa_alloc_table
/**
 * arch_cpa_alloc_table - allocate a page table to split a leaf
 * @req: the request
 * @level: level of the entries in the new table
 * @addr: virtual address mapped by the new table
 *
 * The default implementation cannot allocate tables for CPA_ATOMIC requests.
 *
 * Return: the new table or NULL.
 */
static inline void *arch_cpa_alloc_table(struct cpa_req *req,
					 enum pgtable_level level,
					 unsigned long addr)
{
	if (req->flags & CPA_ATOMIC)
		return NULL;

	switch (level) {
	case PGTABLE_LEVEL_PTE:
		return pte_alloc_one_kernel(&init_mm);
	case PGTABLE_LEVEL_PMD:
		return pmd_alloc_one(&init_mm, addr);
	case PGTABLE_LEVEL_PUD:
		return pud_alloc_one(&init_mm, addr);
	default:
		return NULL;
	}
}
#endif

#ifndef arch_cpa_free_table
/**
 * arch_cpa_free_table - free a page table
 * @req: the request
 * @level: level of the entries in the table
 * @table: the table
 */
static inline void arch_cpa_free_table(struct cpa_req *req,
				       enum pgtable_level level, void *table)
{
	switch (level) {
	case PGTABLE_LEVEL_PTE:
		pte_free_kernel(&init_mm, table);
		break;
	case PGTABLE_LEVEL_PMD:
		pmd_free(&init_mm, table);
		break;
	case PGTABLE_LEVEL_PUD:
		pud_free(&init_mm, table);
		break;
	default:
		break;
	}
}
#endif

#ifndef arch_cpa_split
/**
 * arch_cpa_split - replace a leaf with a table
 * @req: the request
 * @leaf: the leaf
 * @table: page table for the level below @leaf->level
 *
 * Fill @table with entries that map the range of @leaf to the same pfns
 * with the same attributes and install @table instead of @leaf. Perform
 * any TLB maintenance the architecture requires to change the size of a
 * mapping.
 *
 * Return: 0 on success or a negative error code. On error @table is
 * freed by the core.
 */
static inline int arch_cpa_split(struct cpa_req *req, struct cpa_leaf *leaf,
				 void *table)
{
	return -EOPNOTSUPP;
}
#endif

#ifndef arch_cpa_split_group
/**
 * arch_cpa_split_group - split a contiguous group of entries
 * @req: the request
 * @leaf: the leaf with @leaf->nr larger than one
 *
 * Replace the entries of @leaf with entries of the same level that map the
 * same pfns with the same attributes and are not part of a contiguous
 * group. Perform any TLB maintenance the architecture requires.
 *
 * Return: 0 on success or a negative error code.
 */
static inline int arch_cpa_split_group(struct cpa_req *req,
				       struct cpa_leaf *leaf)
{
	return -EOPNOTSUPP;
}
#endif

#ifndef arch_cpa_can_collapse
/**
 * arch_cpa_can_collapse - check if tables can be replaced with leaves
 * @req: the request
 * @level: level of the leaf that would replace a table
 *
 * Return: true if arch_cpa_collapse() can install leaves at @level.
 */
static inline bool arch_cpa_can_collapse(struct cpa_req *req,
					 enum pgtable_level level)
{
	return false;
}
#endif

#ifndef arch_cpa_collapse
/**
 * arch_cpa_collapse - replace a table with a leaf
 * @req: the request
 * @leaf: the leaf to install instead of the table at @leaf->entry
 *
 * The table maps the range of @leaf to the same pfns with the same
 * protections. The core frees the table as soon as this function returns,
 * so the architecture must invalidate TLB and page walk caches for the
 * range before returning.
 *
 * Return: true if the table was replaced.
 */
static inline bool arch_cpa_collapse(struct cpa_req *req,
				     struct cpa_leaf *leaf)
{
	return false;
}
#endif

#ifndef arch_cpa_get_alias
/**
 * arch_cpa_get_alias - get an alias of a part of a request
 * @req: the request
 * @range: the range of the request
 * @addr: start of the part of @range
 * @pfn: first pfn mapped at @addr
 * @nr: number of pages in the part of @range
 * @idx: index of the alias
 * @alias: the alias
 *
 * Aliases are other virtual addresses that map the same pfns as the
 * request and must be changed together with the request, for example the
 * direct map alias of vmalloc pages. Set the range of the alias and the
 * protections to change in it. Holes in the aliases are skipped.
 *
 * Return: false if there is no alias with index @idx.
 */
static inline bool arch_cpa_get_alias(struct cpa_req *req,
				      struct cpa_range *range,
				      unsigned long addr, unsigned long pfn,
				      unsigned long nr, unsigned int idx,
				      struct cpa_range *alias)
{
	return false;
}
#endif

#ifndef arch_cpa_hole
/**
 * arch_cpa_hole - handle an unmapped address
 * @req: the request
 * @addr: the unmapped address
 *
 * Return: 0 to skip the unmapped range or a negative error code to fail the
 * request.
 */
static inline int arch_cpa_hole(struct cpa_req *req, unsigned long addr)
{
	return -EFAULT;
}
#endif

#ifndef arch_cpa_enter
/**
 * arch_cpa_enter - start updating the leaves of a request
 * @req: the request
 */
static inline void arch_cpa_enter(struct cpa_req *req)
{
}
#endif

#ifndef arch_cpa_leave
/**
 * arch_cpa_leave - finish updating the leaves of a request
 * @req: the request
 */
static inline void arch_cpa_leave(struct cpa_req *req)
{
}
#endif

#ifndef arch_cpa_flush
/**
 * arch_cpa_flush - flush the TLB after updating the leaves of a request
 * @req: the request
 *
 * Flush the TLB for [@req->flush_start, @req->flush_end) and for
 * [@req->alias_flush_start, @req->alias_flush_end). Empty ranges have
 * start larger than end.
 */
static inline void arch_cpa_flush(struct cpa_req *req)
{
	if (req->flush_start < req->flush_end)
		flush_tlb_kernel_range(req->flush_start, req->flush_end);
	if (req->alias_flush_start < req->alias_flush_end)
		flush_tlb_kernel_range(req->alias_flush_start,
				       req->alias_flush_end);
}
#endif

#ifndef arch_cpa_test_prot
/**
 * arch_cpa_test_prot - get a software bit for the self test
 *
 * The bit must be ignored by the hardware and preserved by splits and
 * collapses.
 *
 * Return: the bit or 0 if there are no free software bits.
 */
static inline pgprot_t arch_cpa_test_prot(void)
{
	return __pgprot(0);
}
#endif

#endif /* _LINUX_PAGEATTR_H */
