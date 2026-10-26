/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_X86_PAGEATTR_H
#define _ASM_X86_PAGEATTR_H

int arch_cpa_check_range(struct cpa_req *req);
#define arch_cpa_check_range arch_cpa_check_range

bool arch_cpa_new_prot(struct cpa_req *req, struct cpa_range *range,
		       struct cpa_leaf *leaf, unsigned long start,
		       unsigned long end, pgprot_t *prot);
#define arch_cpa_new_prot arch_cpa_new_prot

int arch_cpa_split(struct cpa_req *req, struct cpa_leaf *leaf, void *table);
#define arch_cpa_split arch_cpa_split

bool arch_cpa_can_collapse(struct cpa_req *req, enum pgtable_level level);
#define arch_cpa_can_collapse arch_cpa_can_collapse

bool arch_cpa_collapse(struct cpa_req *req, struct cpa_leaf *leaf);
#define arch_cpa_collapse arch_cpa_collapse

bool arch_cpa_get_alias(struct cpa_req *req, struct cpa_range *range,
			unsigned long addr, unsigned long pfn,
			unsigned long nr, unsigned int idx,
			struct cpa_range *alias);
#define arch_cpa_get_alias arch_cpa_get_alias

int arch_cpa_hole(struct cpa_req *req, unsigned long addr);
#define arch_cpa_hole arch_cpa_hole

void arch_cpa_flush(struct cpa_req *req);
#define arch_cpa_flush arch_cpa_flush

/* the special bit is only used in user mappings */
static inline pgprot_t arch_cpa_test_prot(void)
{
	return __pgprot(_PAGE_SOFTW1);
}
#define arch_cpa_test_prot arch_cpa_test_prot

#endif /* _ASM_X86_PAGEATTR_H */
