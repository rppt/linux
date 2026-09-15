// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Loongson Technology Corporation Limited
 */

#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>
#include <asm/set_memory.h>
#include <asm/tlbflush.h>

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

	old = ptep_get(sd->kpte);
	val = pte_val(old);
	new_val = set_pageattr_masks(cpa, val);

	cpa->pfn = pte_pfn(old) + ((sd->address & (sd->psize - 1)) >> PAGE_SHIFT);

	if (new_val != val) {
		set_pte(sd->kpte, __pte(new_val));
		cpa->state |= CPA_FLUSHTLB;
	}

	return 0;
}

int arch_split_large_page(struct cpa_data *cpa, struct cpa_split_data *sd)
{
	WARN_ON_ONCE(1);

	return -EINVAL;
}

void arch_change_pte(struct cpa_data *cpa, unsigned long address,
		     pte_t *kpte, pte_t old_pte, bool nx, bool rw)
{
	unsigned long val = pte_val(old_pte);
	pte_t new_pte = __pte(set_pageattr_masks(cpa, val));

	cpa->pfn = pte_pfn(old_pte);

	if (pte_val(old_pte) != pte_val(new_pte)) {
		set_pte(kpte, new_pte);
		cpa->state |= CPA_FLUSHTLB;
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

int arch_cpa_process_alias(struct cpa_data *cpa)
{
	return 0;
}

void arch_cpa_finish(struct cpa_data *cpa, int err)
{
	if (err || (cpa->state & CPA_FORCE_FLUSH_ALL) ||
	    (cpa->flags & (CPA_ARRAY | CPA_PAGES_ARRAY))) {
		flush_tlb_all();
		return;
	}

	flush_tlb_kernel_range(*cpa->vaddr, *cpa->vaddr + cpa->numpages * PAGE_SIZE);
}

const struct cpa_operation arch_cpa_operations[CPA_OP_COUNT] = {
	[CPA_SET_RO] = CPA_PROT(0, _PAGE_WRITE | _PAGE_DIRTY, 0),
	[CPA_SET_RW] = CPA_PROT(_PAGE_WRITE | _PAGE_DIRTY, 0, 0),
	[CPA_SET_X] = CPA_PROT(0, _PAGE_NO_EXEC, 0),
	[CPA_SET_NX] = CPA_PROT(_PAGE_NO_EXEC, 0, 0),
};

int arch_cpa_prepare(unsigned long addr, unsigned long numpages,
		     struct cpa_operation *op)
{
	/* The fixed direct window has no page tables to update. */
	if (addr < vm_map_base) {
		op->mask_set = __pgprot(0);
		op->mask_clr = __pgprot(0);
	}

	return 0;
}

bool kernel_page_present(struct page *page)
{
	unsigned int level;
	unsigned long addr = (unsigned long)page_address(page);
	pte_t *pte;

	if (addr < vm_map_base)
		return memblock_is_memory(__pa(addr));

	pte = lookup_address(addr, &level);
	if (!pte)
		return false;

	return pte_present(ptep_get(pte));
}
