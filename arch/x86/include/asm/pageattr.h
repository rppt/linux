/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PAGEATTR_H
#define _ASM_X86_PAGEATTR_H

#include <linux/spinlock.h>
#include <asm/page.h>
#include <asm/pgtable.h>

struct cpa_data;

/*
 * CPA walks the kernel page tables, so it has to serialize against everything
 * else that does, not just against other CPA calls.
 */
static inline void cpa_pgtable_lock(void)
{
	spin_lock(&pgd_lock);
}

static inline void cpa_pgtable_unlock(void)
{
	spin_unlock(&pgd_lock);
}

int cpa_process_alias(struct cpa_data *cpa);
void cpa_flush(struct cpa_data *cpa);
int collapse_large_pages(unsigned long addr, struct list_head *pgtables);

#endif /* _ASM_X86_PAGEATTR_H */
