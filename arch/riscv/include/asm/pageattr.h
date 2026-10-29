/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_RISCV_PAGEATTR_H
#define _ASM_RISCV_PAGEATTR_H

int arch_cpa_split(struct cpa_req *req, struct cpa_leaf *leaf);
#define arch_cpa_split arch_cpa_split

#endif /* _ASM_RISCV_PAGEATTR_H */
