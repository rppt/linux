/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_PAGEATTR_H
#define _ASM_RISCV_PAGEATTR_H

#include <linux/mmzone.h>
#include <asm/page.h>

struct cpa_data;

/*
 * On 64-bit the kernel image, vmalloc and modules are aliased by the linear
 * mapping, and a change to them has to be applied to the linear alias as well.
 *
 * Keep this inline: it runs once per page and says no most of the time.
 */
static inline bool arch_cpa_needs_alias(unsigned long vaddr, unsigned long pfn)
{
	return IS_ENABLED(CONFIG_64BIT) && !is_linear_mapping(vaddr) &&
	       pfn_valid(pfn);
}
#define arch_cpa_needs_alias arch_cpa_needs_alias

int arch_cpa_process_alias(struct cpa_data *cpa);
#define arch_cpa_process_alias arch_cpa_process_alias

#endif /* _ASM_RISCV_PAGEATTR_H */
