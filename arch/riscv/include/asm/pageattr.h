/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_PAGEATTR_H
#define _ASM_RISCV_PAGEATTR_H

#include <asm/pgtable-bits.h>

struct cpa_data;

#define PAGE_CPA_TEST	__pgprot(_PAGE_SOFT & ~_PAGE_SPECIAL)

int arch_cpa_process_alias(struct cpa_data *cpa);
#define arch_cpa_process_alias arch_cpa_process_alias

#endif /* _ASM_RISCV_PAGEATTR_H */
