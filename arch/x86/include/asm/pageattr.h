/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_PAGEATTR_H
#define _ASM_X86_PAGEATTR_H

int arch_cpa_check(struct cpa_req *req);
#define arch_cpa_check arch_cpa_check

bool arch_cpa_new_prot(struct cpa_req *req, struct cpa_range *range,
		       struct cpa_leaf *leaf, unsigned long start,
		       unsigned long end, pgprot_t *prot);
#define arch_cpa_new_prot arch_cpa_new_prot

int arch_cpa_split(struct cpa_req *req, struct cpa_leaf *leaf);
#define arch_cpa_split arch_cpa_split

bool arch_cpa_collapse(struct cpa_req *req, struct cpa_leaf *leaf);
#define arch_cpa_collapse arch_cpa_collapse

bool arch_cpa_image(unsigned long *start, unsigned long *end);
#define arch_cpa_image arch_cpa_image

#define arch_cpa_stats_dir	arch_debugfs_dir

#define arch_direct_map_levels()					\
	(BIT(PGTABLE_LEVEL_PTE) | BIT(PGTABLE_LEVEL_PMD) |		\
	 (direct_gbpages ? BIT(PGTABLE_LEVEL_PUD) : 0))

#endif /* _ASM_X86_PAGEATTR_H */
