// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2019 SiFive
 */

#include <linux/mm.h>
#include <linux/pageattr.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>
#include <linux/vmalloc.h>

#include <asm/tlbflush.h>

/*
 * Every level of the RISC-V page tables encodes a mapping the same way, so
 * the pfn and the protections of a leaf can be read and written without
 * knowing which level it lives at.
 */
static unsigned long cpa_leaf_pfn(struct cpa_leaf *leaf)
{
	return __page_val_to_pfn(pte_val(leaf->pte));
}

static pgprot_t cpa_leaf_prot(struct cpa_leaf *leaf)
{
	return __pgprot(pte_val(leaf->pte) & ~_PAGE_PFN_MASK);
}

static pgprot_t cpa_new_prot(struct cpa_data *cpa, pgprot_t prot)
{
	pgprot_val(prot) &= ~pgprot_val(cpa->mask_clr);
	pgprot_val(prot) |= pgprot_val(cpa->mask_set);

	return prot;
}

pte_t *lookup_address_in_pgd_attr(pgd_t *pgd, unsigned long address,
				  enum pgtable_level *level, bool *nx, bool *rw)
{
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	/* Table entries carry no permissions of their own. */
	*nx = false;
	*rw = true;

	*level = PGTABLE_LEVEL_PGD;
	if (pgd_none(pgdp_get(pgd)))
		return NULL;

	*level = PGTABLE_LEVEL_P4D;
	p4d = p4d_offset(pgd, address);
	if (p4d_none(p4dp_get(p4d)))
		return NULL;

	/*
	 * Sv57 maps the linear mapping with P4D leaves, but RISC-V has no
	 * p4d_leaf() because the generic one must stay constant false, so
	 * decode the entry here.
	 */
	if (pgtable_l5_enabled && (p4d_val(p4dp_get(p4d)) & _PAGE_LEAF))
		return (pte_t *)p4d;

	*level = PGTABLE_LEVEL_PUD;
	pud = pud_offset(p4d, address);
	if (pud_none(pudp_get(pud)))
		return NULL;

	if (pud_leaf(pudp_get(pud)))
		return (pte_t *)pud;

	*level = PGTABLE_LEVEL_PMD;
	pmd = pmd_offset(pud, address);
	if (pmd_none(pmdp_get(pmd)))
		return NULL;

	if (pmd_leaf(pmdp_get(pmd)))
		return (pte_t *)pmd;

	*level = PGTABLE_LEVEL_PTE;

	return pte_offset_kernel(pmd, address);
}

int arch_cpa_aliases(struct cpa_data *cpa, unsigned long vaddr,
		     struct cpa_alias *aliases)
{
	aliases[0].addr = (unsigned long)__va(cpa->pfn << PAGE_SHIFT);
	/* The linear mapping must not become executable. */
	aliases[0].keep = __pgprot(_PAGE_EXEC);
	aliases[0].ignore_err = false;

	return 1;
}

int arch_should_split_large_page(struct cpa_data *cpa, struct cpa_leaf *leaf)
{
	unsigned long lpaddr = leaf->address & pgtable_level_mask(leaf->level);
	unsigned long numpages = leaf->psize >> PAGE_SHIFT;
	pgprot_t old_prot = cpa_leaf_prot(leaf);
	pgprot_t new_prot = cpa_new_prot(cpa, old_prot);

	leaf->pfn = cpa_leaf_pfn(leaf);

	if (pgprot_val(new_prot) == pgprot_val(old_prot))
		return 0;

	/* The change covers only part of the leaf, it has to be split. */
	if (leaf->address != lpaddr || cpa->numpages < numpages)
		return 1;

	set_pte(leaf->kpte, pfn_pte(leaf->pfn, new_prot));
	cpa->state |= CPA_ST_FLUSHTLB;

	return 0;
}

int arch_split_large_page(struct cpa_data *cpa, struct cpa_leaf *leaf,
			      pte_t *pbase)
{
	unsigned long pfn = cpa_leaf_pfn(leaf);
	pgprot_t prot = cpa_leaf_prot(leaf);
	unsigned long size, step;
	int i, nr;

	if (leaf->level < PGTABLE_LEVEL_PMD ||
	    leaf->level > PGTABLE_LEVEL_P4D)
		return 1;

	size = pgtable_level_size(leaf->level - 1);
	step = size >> PAGE_SHIFT;
	nr = leaf->psize / size;

	for (i = 0; i < nr; i++)
		set_pte(pbase + i, pfn_pte(pfn + i * step, prot));

	/* Publish the new table before the entry that points to it. */
	smp_wmb();

	set_pte(leaf->kpte, pfn_pte(virt_to_pfn(pbase), PAGE_TABLE));
	cpa->state |= CPA_ST_FLUSHTLB;

	return 0;
}

void arch_change_pte(struct cpa_data *cpa, struct cpa_leaf *leaf)
{
	unsigned long pfn = cpa_leaf_pfn(leaf);
	pte_t new_pte = pfn_pte(pfn, cpa_new_prot(cpa, cpa_leaf_prot(leaf)));

	cpa->pfn = pfn;

	if (pte_val(leaf->pte) != pte_val(new_pte)) {
		set_pte(leaf->kpte, new_pte);
		cpa->state |= CPA_ST_FLUSHTLB;
	}

	cpa->numpages = 1;
}

int arch_cpa_process_fault(struct cpa_data *cpa, unsigned long vaddr)
{
	return -EINVAL;
}

void arch_cpa_flush(struct cpa_data *cpa, int err)
{
	/*
	 * A change can split a mapping larger than the range it covers, so
	 * the stale entries are not bounded by that range.
	 */
	flush_tlb_all();
}

const struct cpa_op_desc arch_cpa_op_descs[CPA_OP_NUM] = {
	[CPA_SET_RO] = CPA_OP_DESC(_PAGE_READ, _PAGE_WRITE, 0),
	[CPA_SET_RW] = CPA_OP_DESC(_PAGE_READ | _PAGE_WRITE, 0, 0),
	[CPA_SET_X] = CPA_OP_DESC(_PAGE_EXEC, 0, 0),
	[CPA_SET_NX] = CPA_OP_DESC(0, _PAGE_EXEC, 0),
	[CPA_SET_DEFAULT] = CPA_OP_DESC(_PAGE_KERNEL, _PAGE_EXEC,
					CPA_REQ_NO_ALIAS),
	[CPA_SET_INVALID] = CPA_OP_DESC(0, _PAGE_PRESENT, CPA_REQ_NO_ALIAS),
};

void arch_cpa_prepare(struct cpa_op_desc *desc)
{
}

int set_memory_rw_nx(unsigned long addr, int numpages)
{
	return change_page_attr_set_clr(&addr, numpages,
					__pgprot(_PAGE_READ | _PAGE_WRITE),
					__pgprot(_PAGE_EXEC), 0, NULL);
}

#ifdef CONFIG_DEBUG_PAGEALLOC
static int debug_pagealloc_set_page(pte_t *pte, unsigned long addr, void *data)
{
	int enable = *(int *)data;

	unsigned long val = pte_val(ptep_get(pte));

	if (enable)
		val |= _PAGE_PRESENT;
	else
		val &= ~_PAGE_PRESENT;

	set_pte(pte, __pte(val));

	return 0;
}

void __kernel_map_pages(struct page *page, int numpages, int enable)
{
	if (!debug_pagealloc_enabled())
		return;

	unsigned long start = (unsigned long)page_address(page);
	unsigned long size = PAGE_SIZE * numpages;

	apply_to_existing_page_range(&init_mm, start, size, debug_pagealloc_set_page, &enable);

	flush_tlb_kernel_range(start, start + size);
}
#endif

bool kernel_page_present(struct page *page)
{
	unsigned long addr = (unsigned long)page_address(page);
	pgd_t *pgd;
	pud_t *pud;
	p4d_t *p4d;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset_k(addr);
	if (!pgd_present(pgdp_get(pgd)))
		return false;
	if (pgd_leaf(pgdp_get(pgd)))
		return true;

	p4d = p4d_offset(pgd, addr);
	if (!p4d_present(p4dp_get(p4d)))
		return false;
	if (p4d_leaf(p4dp_get(p4d)))
		return true;

	pud = pud_offset(p4d, addr);
	if (!pud_present(pudp_get(pud)))
		return false;
	if (pud_leaf(pudp_get(pud)))
		return true;

	pmd = pmd_offset(pud, addr);
	if (!pmd_present(pmdp_get(pmd)))
		return false;
	if (pmd_leaf(pmdp_get(pmd)))
		return true;

	pte = pte_offset_kernel(pmd, addr);
	return pte_present(ptep_get(pte));
}
