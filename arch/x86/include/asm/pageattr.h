/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PAGEATTR_H
#define _ASM_X86_PAGEATTR_H

#include <asm/pgtable_types.h>

struct cpa_data;
struct cpa_alias;

struct arch_cpa_data {
	pgd_t *pgd;
};

#define CPA_ST_STATIC_PROT	CPA_ST_ARCH(0) /* enforce static protections */

int arch_cpa_aliases(struct cpa_data *cpa, unsigned long vaddr,
		     struct cpa_alias *aliases);
#define arch_cpa_aliases arch_cpa_aliases
void arch_cpa_flush(struct cpa_data *cpa, int err);
#define arch_cpa_flush arch_cpa_flush
void arch_cpa_collapse(struct cpa_data *cpa);
#define arch_cpa_collapse arch_cpa_collapse

#endif /* _ASM_X86_PAGEATTR_H */
