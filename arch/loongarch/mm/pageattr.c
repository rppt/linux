// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Loongson Technology Corporation Limited
 */

#include <linux/mm.h>
#include <linux/pageattr.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>

#include <asm/tlbflush.h>

/*
 * A huge entry carries _PAGE_HUGE where a PTE carries _PAGE_GLOBAL, and its
 * global bit lives at _PAGE_HGLOBAL instead.  The two formats have to be
 * converted into each other when a huge entry is built from or broken into
 * PTEs.
 */
static pgprot_t cpa_prot_huge_2_4k(pgprot_t prot)
{
	unsigned long val = pgprot_val(prot) & ~_PAGE_HUGE;

	if (val & _PAGE_HGLOBAL)
		val = (val & ~_PAGE_HGLOBAL) | _PAGE_GLOBAL;

	return __pgprot(val);
}

static pgprot_t cpa_prot_4k_2_huge(pgprot_t prot)
{
	unsigned long val = pgprot_val(prot);

	if (val & _PAGE_GLOBAL)
		val = (val & ~_PAGE_GLOBAL) | _PAGE_HGLOBAL;

	return __pgprot(val | _PAGE_HUGE);
}

/*
 * With 4K pages _PAGE_HGLOBAL is the lowest bit of _PFN_MASK.  A huge entry
 * maps its PFN aligned to the entry size, so the bit never belongs to the PFN
 * and has to be split off from it by hand.
 */
static unsigned long cpa_leaf_pfn(struct cpa_leaf *leaf)
{
	unsigned long val = pte_val(leaf->pte);

	if (leaf->level != PGTABLE_LEVEL_PTE)
		val &= ~_PAGE_HGLOBAL;

	return (val & _PFN_MASK) >> PFN_PTE_SHIFT;
}

/* The protections of a leaf, always in 4K format. */
static pgprot_t cpa_leaf_prot(struct cpa_leaf *leaf)
{
	unsigned long val = pte_val(leaf->pte);

	if (leaf->level == PGTABLE_LEVEL_PTE)
		return __pgprot(val & ~_PFN_MASK);

	return cpa_prot_huge_2_4k(__pgprot(val & (~_PFN_MASK | _PAGE_HGLOBAL)));
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

	/*
	 * Everything below vm_map_base is reached through a direct mapping
	 * window and has no page table entry.  Stop here rather than index
	 * the kernel pgd with an address it does not describe.
	 */
	if (address < vm_map_base)
		return NULL;

	*level = PGTABLE_LEVEL_PGD;
	if (pgd_none(pgdp_get(pgd)))
		return NULL;

	*level = PGTABLE_LEVEL_P4D;
	p4d = p4d_offset(pgd, address);
	if (p4d_none(p4dp_get(p4d)))
		return NULL;

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

	set_pte(leaf->kpte, pfn_pte(leaf->pfn, cpa_prot_4k_2_huge(new_prot)));
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

	if (leaf->level != PGTABLE_LEVEL_PMD &&
	    leaf->level != PGTABLE_LEVEL_PUD)
		return 1;

	size = pgtable_level_size(leaf->level - 1);
	step = size >> PAGE_SHIFT;
	nr = leaf->psize / size;

	/* A PUD leaf breaks into PMD leaves, which are huge entries too. */
	if (leaf->level == PGTABLE_LEVEL_PUD)
		prot = cpa_prot_4k_2_huge(prot);

	for (i = 0; i < nr; i++)
		set_pte(pbase + i, pfn_pte(pfn + i * step, prot));

	/* Publish the new table before the entry that points to it. */
	smp_wmb();

	/* A table entry holds the virtual address of the table. */
	set_pte(leaf->kpte, __pte((unsigned long)pbase));
	cpa->state |= CPA_ST_FLUSHTLB | CPA_ST_FLUSHTLB_ALL;

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
	unsigned long start, end;

	if (err || (cpa->state & CPA_ST_FLUSHTLB_ALL) ||
	    (cpa->req & (CPA_REQ_ARRAY | CPA_REQ_PAGES_ARRAY))) {
		flush_tlb_all();
		return;
	}

	start = __cpa_addr(cpa, 0) & PAGE_MASK;
	end = start + cpa->numpages * PAGE_SIZE;

	flush_tlb_kernel_range(start, end);
}

const struct cpa_op_desc arch_cpa_op_descs[CPA_OP_NUM] = {
	[CPA_SET_RO] = CPA_OP_DESC(0, _PAGE_WRITE | _PAGE_DIRTY, 0),
	[CPA_SET_RW] = CPA_OP_DESC(_PAGE_WRITE | _PAGE_DIRTY, 0, 0),
	[CPA_SET_X] = CPA_OP_DESC(0, _PAGE_NO_EXEC, 0),
	[CPA_SET_NX] = CPA_OP_DESC(_PAGE_NO_EXEC, 0, 0),
};

void arch_cpa_prepare(struct cpa_op_desc *desc)
{
}
