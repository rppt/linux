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

/**
 * struct cpa_req - a request to change kernel page table permissions
 * @addr: page aligned start of the virtual address range
 * @numpages: number of pages in the range
 * @set: protection bits to set
 * @clr: protection bits to clear
 * @flags: CPA_* request flags
 * @flush_start: start of the range that needs a TLB flush, set by the core
 * @flush_end: end of the range that needs a TLB flush, set by the core
 *
 * A request either succeeds or fails before any permission is changed.
 */
struct cpa_req {
	unsigned long addr;
	unsigned long numpages;
	pgprot_t set;
	pgprot_t clr;
	unsigned int flags;

	unsigned long flush_start;
	unsigned long flush_end;
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

#ifdef CONFIG_GENERIC_PAGEATTR
#include <asm/pageattr.h>
#endif

/*
 * Mandatory architecture hooks.
 */

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
 * @leaf: the leaf
 * @start: start of the part of @leaf covered by the request
 * @end: end of the part of @leaf covered by the request
 * @prot: the new protections
 *
 * Return: false if the new protections are not the same for the whole
 * [@start, @end) range.
 */
static inline bool arch_cpa_new_prot(struct cpa_req *req,
				     struct cpa_leaf *leaf,
				     unsigned long start, unsigned long end,
				     pgprot_t *prot)
{
	*prot = __pgprot((pgprot_val(leaf->prot) & ~pgprot_val(req->clr)) |
			 pgprot_val(req->set));
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
 * Return: the new table or NULL.
 */
static inline void *arch_cpa_alloc_table(struct cpa_req *req,
					 enum pgtable_level level,
					 unsigned long addr)
{
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
 * Flush the TLB for [@req->flush_start, @req->flush_end).
 */
static inline void arch_cpa_flush(struct cpa_req *req)
{
	flush_tlb_kernel_range(req->flush_start, req->flush_end);
}
#endif

#endif /* _LINUX_PAGEATTR_H */
