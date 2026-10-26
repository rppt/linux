// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Loongson Technology Corporation Limited
 */

#include <linux/pageattr.h>
#include <asm/tlbflush.h>

void arch_cpa_prot(enum cpa_prot_op op, pgprot_t *set, pgprot_t *clr)
{
	unsigned long s = 0, c = 0;

	switch (op) {
	case CPA_PROT_RO:
		c = _PAGE_WRITE | _PAGE_DIRTY;
		break;
	case CPA_PROT_RW:
		s = _PAGE_WRITE | _PAGE_DIRTY;
		break;
	case CPA_PROT_X:
		c = _PAGE_NO_EXEC;
		break;
	case CPA_PROT_NX:
		s = _PAGE_NO_EXEC;
		break;
	case CPA_PROT_NP:
	case CPA_PROT_INVALID:
		c = _PAGE_PRESENT | _PAGE_VALID;
		break;
	case CPA_PROT_P:
		s = _PAGE_PRESENT | _PAGE_VALID;
		break;
	case CPA_PROT_DEFAULT:
		s = _PAGE_PRESENT | _PAGE_VALID | _PAGE_WRITE | _PAGE_DIRTY;
		break;
	}

	*set = __pgprot(s);
	*clr = __pgprot(c);
}

/* Huge leaves have _PAGE_HUGE in place of _PAGE_GLOBAL and keep it in bit 12 */
static unsigned long cpa_pte_to_huge(unsigned long val)
{
	unsigned long global = val & _PAGE_GLOBAL;

	val &= ~_PAGE_GLOBAL;
	if (global)
		val |= _PAGE_HGLOBAL;

	return val | _PAGE_HUGE;
}

static unsigned long cpa_huge_to_pte(unsigned long val)
{
	unsigned long global = val & _PAGE_HGLOBAL;

	val &= ~(_PAGE_HUGE | _PAGE_HGLOBAL);
	if (global)
		val |= _PAGE_GLOBAL;

	return val;
}

void arch_cpa_read_leaf(struct cpa_leaf *leaf)
{
	unsigned long val;

	switch (leaf->level) {
	case PGTABLE_LEVEL_PTE:
		val = pte_val(ptep_get((pte_t *)leaf->entry));
		break;
	case PGTABLE_LEVEL_PMD:
		val = cpa_huge_to_pte(pmd_val(pmdp_get((pmd_t *)leaf->entry)));
		break;
	default:
		val = cpa_huge_to_pte(pud_val(pudp_get((pud_t *)leaf->entry)));
		break;
	}

	leaf->pfn = (val & _PFN_MASK) >> PFN_PTE_SHIFT;
	leaf->prot = __pgprot(val & ~_PFN_MASK);
}

void arch_cpa_write_leaf(struct cpa_req *req, struct cpa_leaf *leaf,
			 pgprot_t prot)
{
	unsigned long val = (leaf->pfn << PFN_PTE_SHIFT) | pgprot_val(prot);

	switch (leaf->level) {
	case PGTABLE_LEVEL_PTE:
		set_pte(leaf->entry, __pte(val));
		break;
	case PGTABLE_LEVEL_PMD:
		set_pmd(leaf->entry, __pmd(cpa_pte_to_huge(val)));
		break;
	default:
		set_pud(leaf->entry, __pud(cpa_pte_to_huge(val)));
		break;
	}
}

/*
 * The new PTEs map the same pfns with the same attributes as the huge leaf,
 * so the TLB may hold either of them until the flush without any conflict.
 */
int arch_cpa_split(struct cpa_req *req, struct cpa_leaf *leaf, void *table)
{
	pte_t *ptep = table;
	unsigned int i;

	if (leaf->level != PGTABLE_LEVEL_PMD)
		return -EOPNOTSUPP;

	for (i = 0; i < PTRS_PER_PTE; i++)
		ptep[i] = pfn_pte(leaf->pfn + i, leaf->prot);

	smp_wmb();
	pmd_populate_kernel(&init_mm, leaf->entry, ptep);
	flush_tlb_kernel_range(leaf->start, leaf->start + leaf->size);

	return 0;
}
