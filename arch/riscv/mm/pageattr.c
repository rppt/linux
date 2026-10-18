// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2019 SiFive
 */

#include <linux/pageattr.h>
#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>

#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

static void cpa_update_leaf(struct cpa_data *cpa, struct cpa_leaf *leaf,
			    pte_t pte)
{
	set_pte(leaf->kpte, pte);
	cpa->state |= CPA_ST_FLUSHTLB;

	/* The TLB may still hold the invalid entry */
	if (!(pte_val(leaf->pte) & _PAGE_PRESENT) &&
	    (pte_val(pte) & _PAGE_PRESENT))
		mark_new_valid_map();
}

/* pXd_leaf() can't be used because a leaf may have _PAGE_PRESENT cleared */
static bool cpa_is_leaf(unsigned long val)
{
	return val & _PAGE_LEAF;
}

/*
 * Every level of the page tables encodes a leaf the same way, so its pfn and
 * protections can be read and written without knowing the level.
 */
static pte_t *cpa_set_leaf(struct cpa_leaf *leaf, unsigned long address,
			   pte_t *kpte, enum pgtable_level level,
			   unsigned long psize)
{
	leaf->address = address;
	leaf->kpte = kpte;
	leaf->pte = ptep_get(kpte);
	leaf->pfn = __page_val_to_pfn(pte_val(leaf->pte));
	leaf->prot = __pgprot(pte_val(leaf->pte) & ~_PAGE_PFN_MASK);
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

	pgd = pgd_offset_k(address);
	if (pgd_none(pgdp_get(pgd)))
		return NULL;

	p4d = p4d_offset(pgd, address);
	if (p4d_none(p4dp_get(p4d)))
		return NULL;
	if (pgtable_l5_enabled && cpa_is_leaf(p4d_val(p4dp_get(p4d))))
		return cpa_set_leaf(leaf, address, (pte_t *)p4d,
				    PGTABLE_LEVEL_P4D, P4D_SIZE);

	pud = pud_offset(p4d, address);
	if (pud_none(pudp_get(pud)))
		return NULL;
	if (IS_ENABLED(CONFIG_64BIT) && cpa_is_leaf(pud_val(pudp_get(pud))))
		return cpa_set_leaf(leaf, address, (pte_t *)pud,
				    PGTABLE_LEVEL_PUD, PUD_SIZE);

	pmd = pmd_offset(pud, address);
	if (pmd_none(pmdp_get(pmd)))
		return NULL;
	if (cpa_is_leaf(pmd_val(pmdp_get(pmd))))
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
	pgprot_t new_prot = cpa_new_prot(cpa, leaf->prot);

	if (pgprot_val(new_prot) == pgprot_val(leaf->prot))
		return 0;

	if (leaf->address != lpaddr || cpa->numpages < numpages)
		return 1;

	cpa_update_leaf(cpa, leaf, pfn_pte(leaf->pfn, new_prot));

	return 0;
}

int arch_cpa_split_large_page(struct cpa_data *cpa, struct cpa_leaf *leaf,
			      pte_t *pbase)
{
	/* A page table at any level holds PTRS_PER_PTE entries */
	unsigned long step = (leaf->psize / PTRS_PER_PTE) >> PAGE_SHIFT;
	int i;

	for (i = 0; i < PTRS_PER_PTE; i++)
		set_pte(pbase + i, pfn_pte(leaf->pfn + i * step, leaf->prot));

	/* Make sure the new table is visible before the entry pointing to it */
	smp_wmb();

	set_pte(leaf->kpte, pfn_pte(virt_to_pfn(pbase), PAGE_TABLE));

	/* The split mapping may be larger than the range being changed */
	cpa->state |= CPA_ST_FLUSHTLB_ALL;

	return 0;
}

void arch_cpa_change_pte(struct cpa_data *cpa, struct cpa_leaf *leaf)
{
	pte_t new_pte = pfn_pte(leaf->pfn, cpa_new_prot(cpa, leaf->prot));

	cpa->pfn = leaf->pfn;

	if (pte_val(leaf->pte) != pte_val(new_pte))
		cpa_update_leaf(cpa, leaf, new_pte);

	cpa->numpages = 1;
}

int arch_cpa_process_fault(struct cpa_data *cpa, unsigned long vaddr)
{
	/* The linear mapping has holes, skip them */
	if ((cpa->state & CPA_ST_ALIAS) || is_linear_mapping(vaddr)) {
		cpa->numpages = 1;
		return 0;
	}

	WARN(1, "CPA: called for zero pte. vaddr = %lx cpa->vaddr = %lx\n",
	     vaddr, cpa->vaddr);
	return -EFAULT;
}

/*
 * On 64-bit the kernel image, vmalloc and modules are aliased by the linear
 * mapping, and a change to them has to be applied to the linear alias as well.
 */
int arch_cpa_process_alias(struct cpa_data *cpa)
{
	unsigned long laddr = (unsigned long)__va(cpa->pfn << PAGE_SHIFT);

	if (!IS_ENABLED(CONFIG_64BIT) ||
	    is_linear_mapping(cpa_addr(cpa, cpa->curpage)) ||
	    !pfn_valid(cpa->pfn))
		return 0;

	/* The linear mapping alias is never made executable */
	return cpa_change_alias(cpa, laddr, __pgprot(_PAGE_EXEC));
}

int set_memory_rw_nx(unsigned long addr, int numpages)
{
	return cpa_set_clr(addr, numpages, __pgprot(_PAGE_READ | _PAGE_WRITE),
			   __pgprot(_PAGE_EXEC), 0, NULL);
}

int set_memory_ro(unsigned long addr, int numpages)
{
	return cpa_set_clr(addr, numpages, __pgprot(_PAGE_READ),
			   __pgprot(_PAGE_WRITE), 0, NULL);
}

int set_memory_rw(unsigned long addr, int numpages)
{
	return change_page_attr_set(addr, numpages,
				    __pgprot(_PAGE_READ | _PAGE_WRITE));
}

int set_memory_x(unsigned long addr, int numpages)
{
	return change_page_attr_set(addr, numpages, __pgprot(_PAGE_EXEC));
}

int set_memory_nx(unsigned long addr, int numpages)
{
	return change_page_attr_clear(addr, numpages, __pgprot(_PAGE_EXEC));
}

int set_direct_map_invalid_noflush(struct page *page, unsigned int nr)
{
	return cpa_change_direct_map(page, nr, __pgprot(0),
				     __pgprot(_PAGE_PRESENT));
}

int set_direct_map_default_noflush(struct page *page, unsigned int nr)
{
	int ret;

	ret = cpa_change_direct_map(page, nr, PAGE_KERNEL,
				    __pgprot(_PAGE_EXEC));

	/* The TLB may still hold the invalid entries */
	mark_new_valid_map();

	return ret;
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
		return pmd_val(pmdp_get(pmd)) & _PAGE_PRESENT;

	/* pte_present() is true for PAGE_KERNEL with _PAGE_PRESENT cleared */
	pte = pte_offset_kernel(pmd, addr);
	return pte_val(ptep_get(pte)) & _PAGE_PRESENT;
}
