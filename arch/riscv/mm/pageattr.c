// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2019 SiFive
 */

#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>
#include <asm/tlbflush.h>

/*
 * Walk the page tables in @pgd to find the entry mapping @address.  Returns a
 * pointer to the leaf (or the first not-present) entry and reports its level
 * in @level.  @nx and @rw carry the leaf's No-eXecute / writable state; on
 * RISC-V only leaf entries hold permission bits, so intermediate levels do not
 * contribute.
 */
pte_t *lookup_address_in_pgd_attr(pgd_t *pgd, unsigned long address,
				  unsigned int *level, bool *nx, bool *rw)
{
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	*level = PGTABLE_LEVEL_PGD;
	*nx = false;
	*rw = true;

	if (pgd_none(pgdp_get(pgd)))
		return NULL;
	if (pgd_leaf(pgdp_get(pgd)))
		return (pte_t *)pgd;

	*level = PGTABLE_LEVEL_P4D;
	p4d = p4d_offset(pgd, address);
	if (p4d_none(p4dp_get(p4d)))
		return NULL;
	if (p4d_leaf(p4dp_get(p4d)) || !p4d_present(p4dp_get(p4d)))
		return (pte_t *)p4d;

	*level = PGTABLE_LEVEL_PUD;
	pud = pud_offset(p4d, address);
	if (pud_none(pudp_get(pud)))
		return NULL;
	if (pud_leaf(pudp_get(pud)) || !pud_present(pudp_get(pud)))
		return (pte_t *)pud;

	*level = PGTABLE_LEVEL_PMD;
	pmd = pmd_offset(pud, address);
	if (pmd_none(pmdp_get(pmd)))
		return NULL;
	if (pmd_leaf(pmdp_get(pmd)) || !pmd_present(pmdp_get(pmd)))
		return (pte_t *)pmd;

	*level = PGTABLE_LEVEL_PTE;
	pte = pte_offset_kernel(pmd, address);
	*nx = !(pte_val(ptep_get(pte)) & _PAGE_EXEC);
	*rw = !!(pte_val(ptep_get(pte)) & _PAGE_WRITE);

	return pte;
}

/*
 * Apply the requested attribute change to a single leaf PTE.  Called by the
 * generic CPA core only for PAGE_SIZE (PTE-level) mappings.
 */
void arch_change_pte(struct cpa_data *cpa, unsigned long address,
		     pte_t *kpte, pte_t old_pte, bool nx, bool rw)
{
	pgprot_t new_prot = pte_pgprot(old_pte);
	unsigned long pfn = pte_pfn(old_pte);
	pte_t new_pte;

	pgprot_val(new_prot) &= ~pgprot_val(cpa->mask_clr);
	pgprot_val(new_prot) |= pgprot_val(cpa->mask_set);

	new_pte = pfn_pte(pfn, new_prot);
	cpa->pfn = pfn;

	if (pte_val(old_pte) != pte_val(new_pte)) {
		set_pte(kpte, new_pte);
		cpa->flags |= CPA_FLUSHTLB;
	}
}

/*
 * Decide whether the large page at @kpte must be split.  If the requested
 * range covers the whole large page the attributes are updated in place and
 * the page is preserved (return 0); otherwise the caller is asked to split it
 * (return 1).  cpa->numpages is trimmed to the part of the request that falls
 * within this large page.
 */
int arch_should_split_large_page(pte_t *kpte, unsigned long address,
				 struct cpa_data *cpa)
{
	unsigned long numpages, lpaddr, old_pfn;
	pgprot_t old_prot, req_prot;
	unsigned int level;
	bool nx, rw;
	pte_t *tmp;

	tmp = _lookup_address_cpa(cpa, address, &level, &nx, &rw);
	if (tmp != kpte)
		return 1;

	/*
	 * RISC-V uses the same layout for leaf entries at every level, so a
	 * large leaf can be read and written through the pte_* helpers.
	 */
	old_prot = pte_pgprot(*kpte);
	old_pfn = pte_pfn(*kpte);

	if (!cpa_large_page_geometry(cpa, address, level, old_pfn,
				     &lpaddr, &numpages))
		return -EINVAL;

	req_prot = old_prot;
	pgprot_val(req_prot) &= ~pgprot_val(cpa->mask_clr);
	pgprot_val(req_prot) |= pgprot_val(cpa->mask_set);

	/* Same protection: nothing to do, keep the large page. */
	if (pgprot_val(req_prot) == pgprot_val(old_prot))
		return 0;

	/* Request does not cover the whole large page: split it. */
	if (address != lpaddr || cpa->numpages != numpages)
		return 1;

	/* Whole large page covered: update the leaf in place. */
	set_pte(kpte, pfn_pte(old_pfn, req_prot));
	cpa->flags |= CPA_FLUSHTLB;

	return 0;
}

/*
 * Split the large page at @kpte into the next smaller level using the
 * page-table page in @ptdesc.  Returns 0 if the split was installed, 1 if it
 * raced with another CPU (the caller then frees @ptdesc).
 */
int arch_split_large_page(struct cpa_data *cpa, pte_t *kpte,
			  unsigned long address, struct ptdesc *ptdesc)
{
	struct page *base = ptdesc_page(ptdesc);
	pte_t *pbase = (pte_t *)page_address(base);
	unsigned long old_pfn, pfninc, psize, i;
	unsigned int level;
	pgprot_t prot;
	bool nx, rw;
	pte_t *tmp;

	tmp = _lookup_address_cpa(cpa, address, &level, &nx, &rw);
	if (tmp != kpte)
		return 1;

	switch (level) {
	case PGTABLE_LEVEL_PMD:
		psize = PMD_SIZE;
		break;
	case PGTABLE_LEVEL_PUD:
		psize = PUD_SIZE;
		break;
	default:
		return 1;
	}

	old_pfn = pte_pfn(*kpte);
	prot = pte_pgprot(*kpte);

	/*
	 * Fill the new next-level table with leaves that inherit the large
	 * leaf's protection.  RISC-V page-table pages hold PTRS_PER_PTE entries
	 * at every level, so the per-entry pfn stride is the large-page size
	 * divided by that count.
	 */
	pfninc = (psize >> PAGE_SHIFT) / PTRS_PER_PTE;
	for (i = 0; i < PTRS_PER_PTE; i++)
		set_pte(pbase + i, pfn_pte(old_pfn + i * pfninc, prot));

	smp_wmb();

	set_pte(kpte, pfn_pte(page_to_pfn(base), PAGE_TABLE));

	/*
	 * The split touched a range larger than the request (the whole large
	 * page), so the final flush in arch_cpa_flush() has to cover everything.
	 */
	cpa->force_flush_all = 1;

	return 0;
}

int arch_cpa_process_fault(struct cpa_data *cpa, unsigned long vaddr,
			   int primary)
{
	/* Alias (secondary) walks may legitimately hit holes; ignore them. */
	if (!primary) {
		cpa->numpages = 1;
		return 0;
	}

	WARN(1, "CPA: called for zero pte, vaddr = %lx\n", vaddr);
	return -EFAULT;
}

/*
 * Keep the linear-map alias of a kernel or vmalloc mapping in sync with the
 * primary mapping.  cpa->pfn identifies the physical page just changed; its
 * linear-map address is the alias that needs the same attributes.
 */
int arch_cpa_process_alias(struct cpa_data *cpa)
{
	struct cpa_data alias_cpa;
	unsigned long laddr = (unsigned long)__va(cpa->pfn << PAGE_SHIFT);
	unsigned long vaddr;

	/* Only pages that are part of the linear map have an alias. */
	if (!is_linear_mapping(laddr))
		return 0;

	/* If the primary mapping is the linear map there is no separate alias. */
	vaddr = __cpa_addr(cpa, cpa->curpage);
	if (is_linear_mapping(vaddr))
		return 0;

	alias_cpa = *cpa;
	alias_cpa.vaddr = &laddr;
	alias_cpa.flags &= ~(CPA_PAGES_ARRAY | CPA_ARRAY);
	alias_cpa.curpage = 0;

	/*
	 * The alias lives at a different address than the primary range, so the
	 * final flush in arch_cpa_flush() has to cover everything.
	 */
	cpa->force_flush_all = 1;

	return __change_page_attr_set_clr(&alias_cpa, 0);
}

void arch_cpa_flush(struct cpa_data *cpa, int err)
{
	unsigned long start;

	/*
	 * Flush the whole kernel TLB when the change reached beyond the
	 * requested range (a split or a linear-map alias), when the addresses
	 * are not a single contiguous range, or on error.  Otherwise a ranged
	 * flush of the request is enough.
	 */
	if (err || cpa->force_flush_all ||
	    (cpa->flags & (CPA_ARRAY | CPA_PAGES_ARRAY))) {
		flush_tlb_all();
		return;
	}

	start = __cpa_addr(cpa, 0);
	flush_tlb_kernel_range(start, start + cpa->numpages * PAGE_SIZE);
}

static int __set_memory(unsigned long addr, int numpages, pgprot_t set_mask,
			pgprot_t clear_mask)
{
	if (!numpages)
		return 0;

	return change_page_attr_set_clr(&addr, numpages, set_mask, clear_mask,
					0, 0, NULL);
}


int set_memory_rw_nx(unsigned long addr, int numpages)
{
	return __set_memory(addr, numpages, __pgprot(_PAGE_READ | _PAGE_WRITE),
			    __pgprot(_PAGE_EXEC));
}

int set_memory_ro(unsigned long addr, int numpages)
{
	return __set_memory(addr, numpages, __pgprot(_PAGE_READ),
			    __pgprot(_PAGE_WRITE));
}

int set_memory_rw(unsigned long addr, int numpages)
{
	return __set_memory(addr, numpages, __pgprot(_PAGE_READ | _PAGE_WRITE),
			    __pgprot(0));
}

int set_memory_x(unsigned long addr, int numpages)
{
	return __set_memory(addr, numpages, __pgprot(_PAGE_EXEC), __pgprot(0));
}

int set_memory_nx(unsigned long addr, int numpages)
{
	return __set_memory(addr, numpages, __pgprot(0), __pgprot(_PAGE_EXEC));
}

int set_direct_map_invalid(const void *addr, unsigned long numpages)
{
	return __set_memory((unsigned long)addr, numpages, __pgprot(0),
			    __pgprot(_PAGE_PRESENT));
}

int set_direct_map_default(const void *addr, unsigned long numpages)
{
	return __set_memory((unsigned long)addr, numpages, PAGE_KERNEL,
			    __pgprot(_PAGE_EXEC));
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
