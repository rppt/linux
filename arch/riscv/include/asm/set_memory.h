/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2019 SiFive
 */

#ifndef _ASM_RISCV_SET_MEMORY_H
#define _ASM_RISCV_SET_MEMORY_H

#ifndef __ASSEMBLER__

#include <linux/mmzone.h>
#include <linux/pgtable.h>

#include <asm/page.h>

/*
 * Functions to change memory attributes.
 */
#ifdef CONFIG_MMU
int set_memory_ro(unsigned long addr, int numpages);
int set_memory_rw(unsigned long addr, int numpages);
int set_memory_x(unsigned long addr, int numpages);
int set_memory_nx(unsigned long addr, int numpages);
int set_memory_rw_nx(unsigned long addr, int numpages);
static __always_inline int set_kernel_memory(char *startp, char *endp,
					     int (*set_memory)(unsigned long start,
							       int num_pages))
{
	unsigned long start = (unsigned long)startp;
	unsigned long end = (unsigned long)endp;
	int num_pages = PAGE_ALIGN(end - start) >> PAGE_SHIFT;

	return set_memory(start, num_pages);
}

/*
 * Everything outside the linear mapping is also mapped there, and a change
 * to one of the two has to be applied to the other.
 *
 * Keep this inline: it runs once per page and says no most of the time.
 */
static inline bool arch_cpa_needs_alias(unsigned long vaddr, unsigned long pfn)
{
	return !is_linear_mapping(vaddr) && pfn_valid(pfn);
}

#define arch_cpa_needs_alias arch_cpa_needs_alias

/* A spare software bit CPA self-test can toggle. */
#define ARCH_PAGE_CPA_TEST	__pgprot(_PAGE_SPECIAL)
#else
static inline int set_memory_ro(unsigned long addr, int numpages) { return 0; }
static inline int set_memory_rw(unsigned long addr, int numpages) { return 0; }
static inline int set_memory_x(unsigned long addr, int numpages) { return 0; }
static inline int set_memory_nx(unsigned long addr, int numpages) { return 0; }
static inline int set_memory_rw_nx(unsigned long addr, int numpages) { return 0; }
static inline int set_kernel_memory(char *startp, char *endp,
				    int (*set_memory)(unsigned long start,
						      int num_pages))
{
	return 0;
}
#endif

int set_direct_map_invalid_noflush(struct page *page, unsigned int nr);
int set_direct_map_default_noflush(struct page *page, unsigned int nr);
bool kernel_page_present(struct page *page);

#endif /* __ASSEMBLER__ */

#if defined(CONFIG_STRICT_KERNEL_RWX)
#ifdef CONFIG_64BIT
#define SECTION_ALIGN (1 << 21)
#else
#define SECTION_ALIGN (1 << 22)
#endif
#else /* !CONFIG_STRICT_KERNEL_RWX */
#define SECTION_ALIGN L1_CACHE_BYTES
#endif /* CONFIG_STRICT_KERNEL_RWX */

#define PECOFF_SECTION_ALIGNMENT        0x1000
#define PECOFF_FILE_ALIGNMENT           0x200

#endif /* _ASM_RISCV_SET_MEMORY_H */
