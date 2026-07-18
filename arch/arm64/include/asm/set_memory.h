/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_ARM64_SET_MEMORY_H
#define _ASM_ARM64_SET_MEMORY_H

#include <asm/mem_encrypt.h>
#include <asm/memory.h>
#include <asm-generic/set_memory.h>

bool can_set_direct_map(void);
#define can_set_direct_map can_set_direct_map

/*
 * Whether the CPA leaf at @vaddr / @pfn has an alias that also needs updating.
 * On arm64 the only alias managed by CPA is the linear map: a linear map
 * primary is that mapping and needs no further work, while a vmalloc or module
 * mapping may have to propagate a read-only change to its linear alias.
 */
#define cpa_should_update_alias cpa_should_update_alias
static inline bool cpa_should_update_alias(unsigned long vaddr, unsigned long pfn)
{
	return !__is_lm_address(vaddr);
}

int set_memory_valid(unsigned long addr, int numpages, int enable);

int set_direct_map_invalid_noflush(struct page *page);
int set_direct_map_default_noflush(struct page *page);
int set_direct_map_valid_noflush(struct page *page, unsigned nr, bool valid);
bool kernel_page_present(struct page *page);

int set_memory_encrypted(unsigned long addr, int numpages);
int set_memory_decrypted(unsigned long addr, int numpages);

#endif /* _ASM_ARM64_SET_MEMORY_H */
