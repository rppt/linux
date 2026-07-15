/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _ASM_ARM64_SET_MEMORY_H
#define _ASM_ARM64_SET_MEMORY_H

#include <asm/mem_encrypt.h>
#include <asm/memory.h>
#include <asm/pgtable-hwdef.h>
#include <asm/pgtable-types.h>
#include <asm-generic/set_memory.h>

extern bool rodata_full;

static inline bool cpa_alias_needs_update(unsigned long vaddr, unsigned long pfn,
					  pgprot_t mask_set, pgprot_t mask_clr)
{
	/* Aliases are only mirrored for read-only changes when rodata_full. */
	if (!rodata_full)
		return false;
	if (pgprot_val(mask_set) != PTE_RDONLY &&
	    pgprot_val(mask_clr) != PTE_RDONLY)
		return false;
	/* No alias when the primary target is in the linear map. */
	return !__is_lm_address(vaddr);
}
#define cpa_alias_needs_update cpa_alias_needs_update

bool can_set_direct_map(void);
#define can_set_direct_map can_set_direct_map

int set_memory_valid(unsigned long addr, int numpages, int enable);

int set_direct_map_invalid(const void *addr, unsigned long numpages);
int set_direct_map_default(const void *addr, unsigned long numpages);
bool kernel_page_present(struct page *page);

int set_memory_encrypted(unsigned long addr, int numpages);
int set_memory_decrypted(unsigned long addr, int numpages);

#endif /* _ASM_ARM64_SET_MEMORY_H */
