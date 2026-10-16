/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_RISCV_PAGEATTR_H
#define _ASM_RISCV_PAGEATTR_H

struct cpa_data;
struct cpa_alias;

struct arch_cpa_data { };

int arch_cpa_aliases(struct cpa_data *cpa, unsigned long vaddr,
		     struct cpa_alias *aliases);
#define arch_cpa_aliases arch_cpa_aliases

/* A software bit the CPA self test toggles. */
#define ARCH_PAGE_CPA_TEST	__pgprot(_PAGE_SPECIAL)

#endif /* _ASM_RISCV_PAGEATTR_H */
