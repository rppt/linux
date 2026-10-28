/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_POWERPC_PAGEATTR_H
#define _ASM_POWERPC_PAGEATTR_H

int arch_cpa_check(struct cpa_req *req);
#define arch_cpa_check arch_cpa_check

#endif /* _ASM_POWERPC_PAGEATTR_H */
