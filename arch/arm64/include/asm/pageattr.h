/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_ARM64_PAGEATTR_H
#define _ASM_ARM64_PAGEATTR_H

int arch_cpa_check_range(struct cpa_req *req);
#define arch_cpa_check_range arch_cpa_check_range

void *arch_cpa_alloc_table(struct cpa_req *req, enum pgtable_level level,
			   unsigned long addr);
#define arch_cpa_alloc_table arch_cpa_alloc_table

int arch_cpa_split(struct cpa_req *req, struct cpa_leaf *leaf, void *table);
#define arch_cpa_split arch_cpa_split

int arch_cpa_split_group(struct cpa_req *req, struct cpa_leaf *leaf);
#define arch_cpa_split_group arch_cpa_split_group

bool arch_cpa_can_collapse(struct cpa_req *req, enum pgtable_level level);
#define arch_cpa_can_collapse arch_cpa_can_collapse

bool arch_cpa_collapse(struct cpa_req *req, struct cpa_leaf *leaf);
#define arch_cpa_collapse arch_cpa_collapse

bool arch_cpa_get_alias(struct cpa_req *req, struct cpa_range *range,
			unsigned long addr, unsigned long pfn,
			unsigned long nr, unsigned int idx,
			struct cpa_range *alias);
#define arch_cpa_get_alias arch_cpa_get_alias

/* page table walks of set_memory() always skipped unmapped ranges */
static inline int arch_cpa_hole(struct cpa_req *req, unsigned long addr)
{
	return 0;
}
#define arch_cpa_hole arch_cpa_hole

static inline void arch_cpa_enter(struct cpa_req *req)
{
	lazy_mmu_mode_enable();
}
#define arch_cpa_enter arch_cpa_enter

static inline void arch_cpa_leave(struct cpa_req *req)
{
	lazy_mmu_mode_disable();
}
#define arch_cpa_leave arch_cpa_leave

void arch_cpa_flush(struct cpa_req *req);
#define arch_cpa_flush arch_cpa_flush

#endif /* _ASM_ARM64_PAGEATTR_H */
