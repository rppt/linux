/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PAGEATTR_H
#define _ASM_X86_PAGEATTR_H

#include <linux/spinlock.h>
#include <asm/pgtable.h>

struct cpa_data;
struct cpa_alias;

struct arch_cpa_data {
	pgd_t *pgd;
};

#define CPA_ST_STATIC_PROT	CPA_ST_ARCH(0) /* enforce static protections */

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

int cpa_aliases(struct cpa_data *cpa, unsigned long vaddr,
		struct cpa_alias *aliases);
void cpa_flush_changes(struct cpa_data *cpa, int err);
void __cpa_collapse_large_pages(struct cpa_data *cpa);

#endif /* _ASM_X86_PAGEATTR_H */
