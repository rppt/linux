// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Loongson Technology Corporation Limited
 */

#include <linux/mm.h>
#include <linux/pageattr.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>

static pte_t *cpa_lookup_pte(unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset_k(addr);
	if (pgd_none(pgdp_get(pgd)))
		return NULL;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(p4dp_get(p4d)))
		return NULL;

	pud = pud_offset(p4d, addr);
	if (pud_none(pudp_get(pud)))
		return NULL;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(pmdp_get(pmd)))
		return NULL;

	/* Splitting huge leaves is not supported */
	if (WARN_ON_ONCE(pmd_leaf(pmdp_get(pmd))))
		return ERR_PTR(-EINVAL);

	return pte_offset_kernel(pmd, addr);
}

int arch_change_page_attr(struct cpa_data *cpa)
{
	unsigned long addr = __cpa_addr(cpa, cpa->curpage);
	pte_t *ptep, old, new;

	/* The direct mapping windows have no page tables */
	if (addr < vm_map_base)
		return -EINVAL;

	ptep = cpa_lookup_pte(addr);
	if (IS_ERR(ptep))
		return PTR_ERR(ptep);

	if (!ptep || pte_none(ptep_get(ptep))) {
		VM_WARN_ONCE(1, "CPA: no mapping for %lx\n", addr);
		return -EFAULT;
	}

	old = ptep_get(ptep);
	new = __pte((pte_val(old) & ~pgprot_val(cpa->mask_clr)) |
		    pgprot_val(cpa->mask_set));
	if (pte_val(new) != pte_val(old)) {
		set_pte(ptep, new);
		cpa->state |= CPA_ST_FLUSHTLB;
	}

	cpa->numpages = 1;
	cpa->pfn = pte_pfn(old);

	return 0;
}

int arch_cpa_op_desc(enum cpa_op op, struct cpa_op_desc *desc)
{
	unsigned long set = 0, clr = 0;

	switch (op) {
	case CPA_SET_RO:
		clr = _PAGE_WRITE | _PAGE_DIRTY;
		break;
	case CPA_SET_RW:
		set = _PAGE_WRITE | _PAGE_DIRTY;
		break;
	case CPA_SET_X:
		clr = _PAGE_NO_EXEC;
		break;
	case CPA_SET_NX:
		set = _PAGE_NO_EXEC;
		break;
	default:
		return -EOPNOTSUPP;
	}

	desc->mask_set = __pgprot(set);
	desc->mask_clr = __pgprot(clr);
	desc->req = 0;

	return 0;
}
