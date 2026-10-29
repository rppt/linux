/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_ARM64_PAGEATTR_H
#define _ASM_ARM64_PAGEATTR_H

int arch_cpa_check(struct cpa_req *req);
#define arch_cpa_check arch_cpa_check

int arch_cpa_split(struct cpa_req *req, struct cpa_leaf *leaf);
#define arch_cpa_split arch_cpa_split

unsigned long arch_direct_map_cont(enum pgtable_level level,
				   unsigned long *size);
#define arch_direct_map_cont arch_direct_map_cont

#define arch_direct_map_levels()					\
	(BIT(PGTABLE_LEVEL_PTE) | BIT(PGTABLE_LEVEL_PMD) |		\
	 (pud_sect_supported() ? BIT(PGTABLE_LEVEL_PUD) : 0))

#endif /* _ASM_ARM64_PAGEATTR_H */
