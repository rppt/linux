// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024 Loongson Technology Corporation Limited
 */

#include <linux/pageattr.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>

#include <asm/tlbflush.h>

/*
 * A huge entry has _PAGE_HUGE where a PTE has _PAGE_GLOBAL, and keeps its
 * global bit at _PAGE_HGLOBAL instead.
 */
static pgprot_t cpa_prot_huge_to_4k(pgprot_t prot)
{
	unsigned long val = pgprot_val(prot) & ~_PAGE_HUGE;

	if (val & _PAGE_HGLOBAL)
		val = (val & ~_PAGE_HGLOBAL) | _PAGE_GLOBAL;

	return __pgprot(val);
}

static pgprot_t cpa_prot_4k_to_huge(pgprot_t prot)
{
	unsigned long val = pgprot_val(prot);

	if (val & _PAGE_GLOBAL)
		val = (val & ~_PAGE_GLOBAL) | _PAGE_HGLOBAL;

	return __pgprot(val | _PAGE_HUGE);
}

/*
 * With 4K pages _PAGE_HGLOBAL is the lowest bit of _PFN_MASK, but it never
 * belongs to the pfn of a huge entry.
 */
static unsigned long cpa_leaf_pfn(struct cpa_leaf *leaf)
{
	unsigned long val = pte_val(leaf->pte);

	if (leaf->level != PGTABLE_LEVEL_PTE)
		val &= ~_PAGE_HGLOBAL;

	return (val & _PFN_MASK) >> PFN_PTE_SHIFT;
}

/* The protections of a leaf in the PTE format */
static pgprot_t cpa_leaf_prot(struct cpa_leaf *leaf)
{
	unsigned long val = pte_val(leaf->pte);

	if (leaf->level == PGTABLE_LEVEL_PTE)
		return __pgprot(val & ~_PFN_MASK);

	return cpa_prot_huge_to_4k(__pgprot(val & (~_PFN_MASK | _PAGE_HGLOBAL)));
}

static pgprot_t cpa_new_prot(struct cpa_data *cpa, pgprot_t prot)
{
	pgprot_val(prot) &= ~pgprot_val(cpa->mask_clr);
	pgprot_val(prot) |= pgprot_val(cpa->mask_set);

	return prot;
}

static pte_t *cpa_set_leaf(struct cpa_leaf *leaf, unsigned long address,
			   pte_t *kpte, enum pgtable_level level,
			   unsigned long psize)
{
	leaf->address = address;
	leaf->kpte = kpte;
	leaf->pte = ptep_get(kpte);
	leaf->level = level;
	leaf->psize = psize;

	return kpte;
}

pte_t *arch_cpa_lookup_leaf(struct cpa_data *cpa, unsigned long address,
			    struct cpa_leaf *leaf)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	/* Addresses below vm_map_base are mapped by DMW, not page tables */
	if (address < vm_map_base)
		return NULL;

	pgd = pgd_offset_k(address);
	if (pgd_none(pgdp_get(pgd)))
		return NULL;

	p4d = p4d_offset(pgd, address);
	if (p4d_none(p4dp_get(p4d)))
		return NULL;

	pud = pud_offset(p4d, address);
	if (pud_none(pudp_get(pud)))
		return NULL;
	if (CONFIG_PGTABLE_LEVELS > 3 && pud_leaf(pudp_get(pud)))
		return cpa_set_leaf(leaf, address, (pte_t *)pud,
				    PGTABLE_LEVEL_PUD, PUD_SIZE);

	pmd = pmd_offset(pud, address);
	if (pmd_none(pmdp_get(pmd)))
		return NULL;
	if (pmd_leaf(pmdp_get(pmd)))
		return cpa_set_leaf(leaf, address, (pte_t *)pmd,
				    PGTABLE_LEVEL_PMD, PMD_SIZE);

	return cpa_set_leaf(leaf, address, pte_offset_kernel(pmd, address),
			    PGTABLE_LEVEL_PTE, PAGE_SIZE);
}

int arch_cpa_should_split_large_page(struct cpa_data *cpa,
				     struct cpa_leaf *leaf)
{
	unsigned long lpaddr = leaf->address & ~(leaf->psize - 1);
	unsigned long numpages = leaf->psize >> PAGE_SHIFT;
	pgprot_t old_prot = cpa_leaf_prot(leaf);
	pgprot_t new_prot = cpa_new_prot(cpa, old_prot);

	if (cpa->req & CPA_REQ_SPLIT)
		return 1;

	leaf->pfn = cpa_leaf_pfn(leaf);

	if (pgprot_val(new_prot) == pgprot_val(old_prot))
		return 0;

	if (leaf->address != lpaddr || cpa->numpages < numpages)
		return 1;

	set_pte(leaf->kpte, pfn_pte(leaf->pfn, cpa_prot_4k_to_huge(new_prot)));
	cpa->state |= CPA_ST_FLUSHTLB;

	return 0;
}

int arch_cpa_split_large_page(struct cpa_data *cpa, struct cpa_leaf *leaf,
			      pte_t *pbase)
{
	/* A page table at any level holds PTRS_PER_PTE entries */
	unsigned long step = (leaf->psize / PTRS_PER_PTE) >> PAGE_SHIFT;
	unsigned long pfn = cpa_leaf_pfn(leaf);
	pgprot_t prot = cpa_leaf_prot(leaf);
	int i;

	/* A PUD leaf is split into PMD leaves */
	if (leaf->level == PGTABLE_LEVEL_PUD)
		prot = cpa_prot_4k_to_huge(prot);

	for (i = 0; i < PTRS_PER_PTE; i++)
		set_pte(pbase + i, pfn_pte(pfn + i * step, prot));

	/* Make sure the new table is visible before the entry pointing to it */
	smp_wmb();

	set_pte(leaf->kpte, __pte((unsigned long)pbase));

	/* The split mapping may be larger than the range being changed */
	cpa->state |= CPA_ST_FLUSHTLB_ALL;

	return 0;
}

void arch_cpa_change_pte(struct cpa_data *cpa, struct cpa_leaf *leaf)
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
	/* Addresses below vm_map_base are mapped by DMW, not page tables */
	if (vaddr < vm_map_base)
		return -EINVAL;

	WARN(1, "CPA: called for zero pte. vaddr = %lx cpa->vaddr = %lx\n",
	     vaddr, cpa->vaddr);
	return -EFAULT;
}

int set_memory_x(unsigned long addr, int numpages)
{
	return change_page_attr_clear(addr, numpages, __pgprot(_PAGE_NO_EXEC));
}

int set_memory_nx(unsigned long addr, int numpages)
{
	return change_page_attr_set(addr, numpages, __pgprot(_PAGE_NO_EXEC));
}

int set_memory_ro(unsigned long addr, int numpages)
{
	return change_page_attr_clear(addr, numpages,
				      __pgprot(_PAGE_WRITE | _PAGE_DIRTY));
}

int set_memory_rw(unsigned long addr, int numpages)
{
	return change_page_attr_set(addr, numpages,
				    __pgprot(_PAGE_WRITE | _PAGE_DIRTY));
}
