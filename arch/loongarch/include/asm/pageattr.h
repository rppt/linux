/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_LOONGARCH_PAGEATTR_H
#define _ASM_LOONGARCH_PAGEATTR_H

#include <asm/addrspace.h>

/*
 * Direct mapped windows are not translated by the page tables. They are
 * below vm_map_base, so a range that starts above it never reaches them.
 */
static inline int arch_cpa_check(struct cpa_req *req)
{
	return req->addr < vm_map_base ? -EINVAL : 0;
}
#define arch_cpa_check arch_cpa_check

int arch_cpa_split(struct cpa_req *req, struct cpa_leaf *leaf);
#define arch_cpa_split arch_cpa_split

#endif /* _ASM_LOONGARCH_PAGEATTR_H */
