// SPDX-License-Identifier: GPL-2.0
#ifndef _INCLUDE_ASI_H
#define _INCLUDE_ASI_H

enum page_table_level {
        PGT_LEVEL_PTE,
        PGT_LEVEL_PMD,
        PGT_LEVEL_PUD,
        PGT_LEVEL_P4D,
        PGT_LEVEL_PGD
};

int asi_clone_pgd_range(struct mm_struct *dst_mm,
			struct mm_struct *src_mm,
			pgd_t *dst_pagetable, pgd_t *src_pagetable,
			unsigned long addr, unsigned long end,
			enum page_table_level level);

int asi_map_range(struct mm_struct *mm, pgd_t *pgd,
		  unsigned long virt, phys_addr_t phys,
		  pgprot_t prot, int nr_pages);

static inline int asi_map_page(struct mm_struct *mm, pgd_t *pgd,
			       unsigned long virt, phys_addr_t phys,
			       pgprot_t prot)
{
	return asi_map_range(mm, pgd, virt, phys, prot, 1);
}


#endif
