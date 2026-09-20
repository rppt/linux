// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Loongson Technology Corporation Limited
 */

#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>
#include <linux/pageattr.h>
#include <asm/set_memory.h>
#include <asm/tlbflush.h>

pte_t *lookup_address_in_pgd_attr(pgd_t *pgdp, unsigned long address,
				  unsigned int *level, bool *nx, bool *rw)
{
	pgd_t pgd;
	p4d_t *p4dp, p4d;
	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;

	*level = PGTABLE_LEVEL_PGD;
	*nx = false;
	*rw = true;

	pgd = pgdp_get(pgdp);
	if (pgd_none(pgd))
		return NULL;

	*level = PGTABLE_LEVEL_P4D;
	p4dp = p4d_offset(pgdp, address);
	p4d = p4dp_get(p4dp);
	if (p4d_none(p4d))
		return NULL;

	if (p4d_leaf(p4d) || !p4d_present(p4d))
		return (pte_t *)p4dp;

	*level = PGTABLE_LEVEL_PUD;
	pudp = pud_offset(p4dp, address);
	pud = pudp_get(pudp);
	if (pud_none(pud))
		return NULL;

	if (pud_leaf(pud) || !pud_present(pud))
		return (pte_t *)pudp;

	*level = PGTABLE_LEVEL_PMD;
	pmdp = pmd_offset(pudp, address);
	pmd = pmdp_get(pmdp);
	if (pmd_none(pmd))
		return NULL;

	if (pmd_leaf(pmd) || !pmd_present(pmd))
		return (pte_t *)pmdp;

	*level = PGTABLE_LEVEL_PTE;
	return pte_offset_kernel(pmdp, address);
}

static unsigned long set_pageattr_masks(struct cpa_data *cpa, unsigned long val)
{
	val &= ~pgprot_val(cpa->mask_clr);
	val |= pgprot_val(cpa->mask_set);

	return val;
}

int arch_should_split_large_page(struct cpa_data *cpa, struct cpa_split_data *sd)
{
	unsigned long val, new_val;
	pte_t old;
	int ret;

	ret = cpa_prepare_split(cpa, sd);
	if (ret)
		return ret;

	if ((sd->address & ~sd->pmask) ||
	    cpa->numpages != sd->psize >> PAGE_SHIFT)
		return -EINVAL;

	old = ptep_get(sd->kpte);
	val = pte_val(old);
	new_val = set_pageattr_masks(cpa, val);

	cpa->pfn = pte_pfn(old) + ((sd->address & (sd->psize - 1)) >> PAGE_SHIFT);

	if (new_val != val) {
		set_pte(sd->kpte, __pte(new_val));
		cpa->state |= CPA_ST_FLUSHTLB;
	}

	return 0;
}

void arch_change_pte(struct cpa_data *cpa, unsigned long address,
		     pte_t *kpte, pte_t old_pte, bool nx, bool rw)
{
	unsigned long val = pte_val(old_pte);
	pte_t new_pte = __pte(set_pageattr_masks(cpa, val));

	cpa->pfn = pte_pfn(old_pte);

	if (pte_val(old_pte) != pte_val(new_pte)) {
		set_pte(kpte, new_pte);
		cpa->state |= CPA_ST_FLUSHTLB;
	}
}

int arch_cpa_process_fault(struct cpa_data *cpa, unsigned long vaddr)
{
	/*
	 * The direct map has no page tables and vmalloc ranges may contain
	 * holes. Both are silently skipped.
	 */
	cpa->numpages = 1;

	return 0;
}

void arch_cpa_finish(struct cpa_data *cpa, int err)
{
	if (!err && !(cpa->state & CPA_ST_FLUSHTLB))
		return;

	if (err || (cpa->state & CPA_ST_FLUSHTLB_ALL) ||
	    (cpa->req & (CPA_REQ_ARRAY | CPA_REQ_PAGES_ARRAY))) {
		flush_tlb_all();
		return;
	}

	flush_tlb_kernel_range(*cpa->vaddr, *cpa->vaddr + cpa->numpages * PAGE_SIZE);
}

const struct cpa_op_desc arch_cpa_op_descs[CPA_OP_NUM] = {
	[CPA_SET_RO] = CPA_OP_DESC(0, _PAGE_WRITE | _PAGE_DIRTY, 0),
	[CPA_SET_RW] = CPA_OP_DESC(_PAGE_WRITE | _PAGE_DIRTY, 0, 0),
	[CPA_SET_X] = CPA_OP_DESC(0, _PAGE_NO_EXEC, 0),
	[CPA_SET_NX] = CPA_OP_DESC(_PAGE_NO_EXEC, 0, 0),
};

int arch_cpa_prepare(struct cpa_data *cpa)
{
	/* The fixed direct window has no page tables to update. */
	if (cpa_addr(cpa, 0) < vm_map_base) {
		cpa->mask_set = __pgprot(0);
		cpa->mask_clr = __pgprot(0);
	}

	return 0;
}
