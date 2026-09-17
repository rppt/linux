/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2024 Loongson Technology Corporation Limited
 */

#ifndef _ASM_LOONGARCH_SET_MEMORY_H
#define _ASM_LOONGARCH_SET_MEMORY_H

/*
 * Functions to change memory attributes.
 */
int set_memory_x(unsigned long addr, int numpages);
int set_memory_nx(unsigned long addr, int numpages);
int set_memory_ro(unsigned long addr, int numpages);
int set_memory_rw(unsigned long addr, int numpages);

/*
 * The direct map is a fixed window, not a page-table mapping. Its permissions
 * cannot be changed to match a page-table alias.
 */
#define arch_cpa_should_update_alias arch_cpa_should_update_alias
static inline bool arch_cpa_should_update_alias(unsigned long vaddr,
						unsigned long pfn)
{
	return false;
}

#endif /* _ASM_LOONGARCH_SET_MEMORY_H */
