/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_ARM64_PAGEATTR_H
#define _ASM_ARM64_PAGEATTR_H

struct cpa_data;
struct cpa_leaf;

int arch_cpa_process_alias(struct cpa_data *cpa);
#define arch_cpa_process_alias arch_cpa_process_alias

int arm64_cpa_prepare_split(struct cpa_leaf *leaf);

/* The lazy MMU mode defers only the barriers */
static inline bool arch_cpa_lazy_mmu(void)
{
	return true;
}
#define arch_cpa_lazy_mmu arch_cpa_lazy_mmu

#endif /* _ASM_ARM64_PAGEATTR_H */
