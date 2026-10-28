// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2024 Loongson Technology Corporation Limited
 */

#include <linux/pageattr.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>

struct cpa_prot_op arch_cpa_prot_ops[CPA_PROT_NR] __ro_after_init = {
	[CPA_PROT_RO] = { .clr = __pgprot(_PAGE_WRITE | _PAGE_DIRTY) },
	[CPA_PROT_RW] = { .set = __pgprot(_PAGE_WRITE | _PAGE_DIRTY) },
	[CPA_PROT_X]  = { .clr = __pgprot(_PAGE_NO_EXEC) },
	[CPA_PROT_NX] = { .set = __pgprot(_PAGE_NO_EXEC) },
	[CPA_PROT_NP] = { .clr = __pgprot(_PAGE_PRESENT | _PAGE_VALID) },
	[CPA_PROT_P]  = { .set = __pgprot(_PAGE_PRESENT | _PAGE_VALID) },
};

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

bool arch_cpa_read_leaf(struct cpa_leaf *leaf)
{
	unsigned long val;

	switch (leaf->level) {
	case PGTABLE_LEVEL_PTE:
		val = pte_val(ptep_get((pte_t *)leaf->entry));
		break;
	case PGTABLE_LEVEL_PMD:
		val = pmd_val(pmdp_get((pmd_t *)leaf->entry));
		break;
	case PGTABLE_LEVEL_PUD:
		val = pud_val(pudp_get((pud_t *)leaf->entry));
		break;
	default:
		return false;
	}

	if (leaf->level != PGTABLE_LEVEL_PTE) {
		if (!(val & _PAGE_HUGE))
			return false;
		val = cpa_huge_to_pte(val);
	}

	leaf->pfn = (val & _PFN_MASK) >> PFN_PTE_SHIFT;
	leaf->prot = __pgprot(val & ~_PFN_MASK);

	return true;
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
	case PGTABLE_LEVEL_PUD:
		set_pud(leaf->entry, __pud(cpa_pte_to_huge(val)));
		break;
	default:
		WARN_ON_ONCE(1);
	}
}

/*
 * The new PTEs map the same pfns with the same attributes as the huge leaf,
 * so the TLB may hold either of them until the flush without any conflict.
 */
int arch_cpa_split(struct cpa_req *req, struct cpa_leaf *leaf)
{
	unsigned int i;
	pte_t *ptep;

	if (leaf->level != PGTABLE_LEVEL_PMD)
		return -EOPNOTSUPP;

	ptep = cpa_alloc_table(req, PGTABLE_LEVEL_PTE, leaf->start);
	if (!ptep)
		return -ENOMEM;

	for (i = 0; i < PTRS_PER_PTE; i++)
		ptep[i] = pfn_pte(leaf->pfn + i, leaf->prot);

	smp_wmb();
	pmd_populate_kernel(&init_mm, leaf->entry, ptep);
	flush_tlb_kernel_range(leaf->start, leaf->start + leaf->size);

	return 0;
}

void arch_cpa_flush(struct cpa_req *req)
{
	if (req->flags & CPA_NOFLUSH)
		return;

	cpa_flush_ranges(req);
}
