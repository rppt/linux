/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arm64 KFENCE support.
 *
 * Copyright (C) 2020, Google LLC.
 */

#ifndef __ASM_KFENCE_H
#define __ASM_KFENCE_H

#include <linux/pgtable.h>

#include <asm/tlbflush.h>

/*
 * The KFENCE pool is always mapped with base pages, and its pages can be
 * protected from any context, so update the PTE directly.
 */
static inline bool kfence_protect_page(unsigned long addr, bool protect)
{
	pte_t *ptep = virt_to_kpte(addr);
	pte_t pte;

	if (WARN_ON_ONCE(!ptep || pte_cont(__ptep_get(ptep))))
		return false;

	pte = __ptep_get(ptep);
	if (protect) {
		__set_pte(ptep, pte_mkinvalid(pte));
		flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
	} else {
		/* Invalid entries are not cached in the TLB */
		__set_pte(ptep, pte_mkvalid_k(pte));
	}

	return true;
}

#ifdef CONFIG_KFENCE
extern bool kfence_early_init;
static inline bool arm64_kfence_can_set_direct_map(void)
{
	return !kfence_early_init;
}
bool arch_kfence_init_pool(void);
#else /* CONFIG_KFENCE */
static inline bool arm64_kfence_can_set_direct_map(void) { return false; }
#endif /* CONFIG_KFENCE */

#endif /* __ASM_KFENCE_H */
