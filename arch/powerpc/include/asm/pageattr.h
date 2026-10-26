/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_POWERPC_PAGEATTR_H
#define _ASM_POWERPC_PAGEATTR_H

int arch_cpa_check_range(struct cpa_req *req);
#define arch_cpa_check_range arch_cpa_check_range

void arch_cpa_leave(struct cpa_req *req);
#define arch_cpa_leave arch_cpa_leave

static inline pgprot_t arch_cpa_test_prot(void)
{
	return __pgprot(_RPAGE_SW1);
}
#define arch_cpa_test_prot arch_cpa_test_prot

#endif /* _ASM_POWERPC_PAGEATTR_H */
