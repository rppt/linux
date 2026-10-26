/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_PAGEATTR_H
#define _ASM_RISCV_PAGEATTR_H

int arch_cpa_split(struct cpa_req *req, struct cpa_leaf *leaf, void *table);
#define arch_cpa_split arch_cpa_split

int arch_cpa_split_group(struct cpa_req *req, struct cpa_leaf *leaf);
#define arch_cpa_split_group arch_cpa_split_group

static inline bool arch_cpa_can_collapse(struct cpa_req *req,
					 enum pgtable_level level)
{
	return true;
}
#define arch_cpa_can_collapse arch_cpa_can_collapse

bool arch_cpa_collapse(struct cpa_req *req, struct cpa_leaf *leaf);
#define arch_cpa_collapse arch_cpa_collapse

bool arch_cpa_get_alias(struct cpa_req *req, struct cpa_range *range,
			unsigned long addr, unsigned long pfn,
			unsigned long nr, unsigned int idx,
			struct cpa_range *alias);
#define arch_cpa_get_alias arch_cpa_get_alias

/* RSW bit that is only used in user mappings */
static inline pgprot_t arch_cpa_test_prot(void)
{
	return __pgprot(BIT(9));
}
#define arch_cpa_test_prot arch_cpa_test_prot

#endif /* _ASM_RISCV_PAGEATTR_H */
