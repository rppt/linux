/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PAGEWALK_H
#define _LINUX_PAGEWALK_H

#include <linux/mm.h>

struct mm_walk;

#define PAGEWALK_ALLOC_PTE (1UL << 0)
#define PAGEWALK_ALLOC_PMD (1UL << 1)
#define PAGEWALK_ALLOC_PUD (1UL << 2)
#define PAGEWALK_ALLOC_P4D (1UL << 3)

/**
 * mm_walk_ops - callbacks for walk_page_range
 * @pgd_entry:		if set, called for each non-empty PGD (top-level) entry
 * @p4d_entry:		if set, called for each non-empty P4D entry
 * @pud_entry:		if set, called for each non-empty PUD (2nd-level) entry
 *			this handler should only handle pud_trans_huge() puds.
 *			the pmd_entry or pte_entry callbacks will be used for
 *			regular PUDs.
 * @pmd_entry:		if set, called for each non-empty PMD (3rd-level) entry
 *			this handler is required to be able to handle
 *			pmd_trans_huge() pmds.  They may simply choose to
 *			split_huge_page() instead of handling it explicitly.
 * @pte_entry:		if set, called for each non-empty PTE (4th-level) entry
 * @pte_hole:		if set, called for each hole at all levels
 * @hugetlb_entry:	if set, called for each hugetlb entry
 * @test_walk:		caller specific callback function to determine whether
 *			we walk over the current vma or not. Returning 0 means
 *			"do page table walk over the current vma", returning
 *			a negative value means "abort current page table walk
 *			right now" and returning 1 means "skip the current vma"
 * @test_pmd:		similar to test_walk(), but called for every pmd.
 * @test_pud:		similar to test_walk(), but called for every pud.
 * @test_p4d:		similar to test_walk(), but called for every p4d.
 *			Returning 0 means walk this part of the page tables,
 *			returning 1 means to skip this range.
 * @flags:		used to specify options for the page walk.
 */
struct mm_walk_ops {
	int (*pgd_entry)(pgd_t *pgd, unsigned long addr,
			 unsigned long next, struct mm_walk *walk);
	int (*p4d_entry)(p4d_t *p4d, unsigned long addr,
			 unsigned long next, struct mm_walk *walk);
	int (*pud_entry)(pud_t *pud, unsigned long addr,
			 unsigned long next, struct mm_walk *walk);
	int (*pmd_entry)(pmd_t *pmd, unsigned long addr,
			 unsigned long next, struct mm_walk *walk);
	int (*pte_entry)(pte_t *pte, unsigned long addr,
			 unsigned long next, struct mm_walk *walk);
	int (*pte_hole)(unsigned long addr, unsigned long next,
			struct mm_walk *walk);
	int (*hugetlb_entry)(pte_t *pte, unsigned long hmask,
			     unsigned long addr, unsigned long next,
			     struct mm_walk *walk);
	int (*test_walk)(unsigned long addr, unsigned long next,
			struct mm_walk *walk);
	int (*test_pmd)(unsigned long addr, unsigned long next,
			pmd_t *pmd_start, struct mm_walk *walk);
	int (*test_pud)(unsigned long addr, unsigned long next,
			pud_t *pud_start, struct mm_walk *walk);
	int (*test_p4d)(unsigned long addr, unsigned long next,
			p4d_t *p4d_start, struct mm_walk *walk);
	unsigned long flags;
};

/**
 * mm_walk - walk_page_range data
 * @ops:	operation to call during the walk
 * @mm:		mm_struct representing the target process of page table walk
 * @vma:	vma currently walked (NULL if walking outside vmas)
 * @private:	private data for callbacks' usage
 *
 * (see the comment on walk_page_range() for more details)
 */
struct mm_walk {
	const struct mm_walk_ops *ops;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	void *private;
};

int walk_page_range(struct mm_struct *mm, unsigned long start,
		unsigned long end, const struct mm_walk_ops *ops,
		void *private);
int walk_page_vma(struct vm_area_struct *vma, const struct mm_walk_ops *ops,
		void *private);

#endif /* _LINUX_PAGEWALK_H */
