/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_PAGEATTR_H
#define _ASM_RISCV_PAGEATTR_H

struct cpa_data;

int arch_cpa_process_alias(struct cpa_data *cpa);
#define arch_cpa_process_alias arch_cpa_process_alias

#endif /* _ASM_RISCV_PAGEATTR_H */
