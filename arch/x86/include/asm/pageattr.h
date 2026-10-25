/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PAGEATTR_H
#define _ASM_X86_PAGEATTR_H

#include <linux/spinlock.h>
#include <asm/page.h>
#include <asm/pgtable.h>

struct cpa_data;

#define PAGE_CPA_TEST	__pgprot(_PAGE_CPA_TEST)

/*
 * CPA walks the kernel page tables, so it has to serialize against everything
 * else that does, not just against other CPA calls.
 */
static inline void arch_cpa_pgtable_lock(void)
{
	spin_lock(&pgd_lock);
}
#define arch_cpa_pgtable_lock arch_cpa_pgtable_lock

static inline void arch_cpa_pgtable_unlock(void)
{
	spin_unlock(&pgd_lock);
}
#define arch_cpa_pgtable_unlock arch_cpa_pgtable_unlock

int arch_cpa_process_alias(struct cpa_data *cpa);
#define arch_cpa_process_alias arch_cpa_process_alias
void arch_cpa_flush(struct cpa_data *cpa);
#define arch_cpa_flush arch_cpa_flush
int arch_cpa_collapse(unsigned long addr, struct list_head *pgtables);
#define arch_cpa_collapse arch_cpa_collapse

#endif /* _ASM_X86_PAGEATTR_H */
