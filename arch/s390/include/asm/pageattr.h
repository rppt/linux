/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_S390_PAGEATTR_H
#define _ASM_S390_PAGEATTR_H

void *arch_cpa_alloc_table(struct cpa_req *req, enum pgtable_level level,
			   unsigned long addr);
#define arch_cpa_alloc_table arch_cpa_alloc_table

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

/* Every change of a valid entry purges the TLB */
static inline void arch_cpa_flush(struct cpa_req *req)
{
}
#define arch_cpa_flush arch_cpa_flush

pgprot_t arch_cpa_test_prot(void);
#define arch_cpa_test_prot arch_cpa_test_prot

#endif /* _ASM_S390_PAGEATTR_H */
