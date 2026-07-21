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

bool kernel_page_present(struct page *page);
#define kernel_page_present kernel_page_present

/*
 * The direct map is a fixed window, not a page-table mapping. Its permissions
 * cannot be changed to match a page-table alias.
 */
static inline bool cpa_should_update_alias(unsigned long vaddr, unsigned long pfn)
{
	return false;
}

#endif /* _ASM_LOONGARCH_SET_MEMORY_H */
