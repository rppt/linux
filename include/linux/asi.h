// SPDX-License-Identifier: GPL-2.0
#ifndef _INCLUDE_LINUX_ASI_H
#define _INCLUDE_LINUX_ASI_H

enum asi_clone_level {
	ASI_LEVEL_LEAF,
        ASI_LEVEL_PTE,
        ASI_LEVEL_PMD,
        ASI_LEVEL_PUD,
        ASI_LEVEL_P4D,
        ASI_LEVEL_PGD,
};

int asi_clone_pgd_range(struct mm_struct *dst_mm,
			struct mm_struct *src_mm,
			pgd_t *dst_pagetable, pgd_t *src_pagetable,
			unsigned long addr, unsigned long end,
			enum asi_clone_level level);

int asi_map_range(struct mm_struct *mm, pgd_t *pgd,
		  unsigned long virt, phys_addr_t phys,
		  pgprot_t prot, int nr_pages);

static inline int asi_map_page(struct mm_struct *mm, pgd_t *pgd,
			       unsigned long virt, phys_addr_t phys,
			       pgprot_t prot)
{
	return asi_map_range(mm, pgd, virt, phys, prot, 1);
}

void asi_exit(struct mm_struct *mm);

#endif /* _INCLUDE_LINUX_ASI_H */
