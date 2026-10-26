/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_LOONGARCH_PAGEATTR_H
#define _ASM_LOONGARCH_PAGEATTR_H

#include <asm/addrspace.h>

/* Direct mapped windows are not translated by the page tables */
static inline int arch_cpa_check_range(struct cpa_req *req)
{
	return req->addr < vm_map_base ? -EINVAL : 0;
}
#define arch_cpa_check_range arch_cpa_check_range

int arch_cpa_split(struct cpa_req *req, struct cpa_leaf *leaf, void *table);
#define arch_cpa_split arch_cpa_split

#ifdef CONFIG_64BIT
/* Bits PALEN..60 are ignored by the hardware */
static inline pgprot_t arch_cpa_test_prot(void)
{
	return __pgprot(BIT_ULL(59));
}
#define arch_cpa_test_prot arch_cpa_test_prot
#endif

#endif /* _ASM_LOONGARCH_PAGEATTR_H */
