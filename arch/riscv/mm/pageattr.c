// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2019 SiFive
 */

#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>

#include <asm/tlbflush.h>
#include <asm/set_memory.h>

static struct cpa_arch_info riscv_cpa_info = {
	.lock = &init_mm.page_table_lock,
};

struct cpa_arch_info *cpa_arch_setup(void)
{
	return &riscv_cpa_info;
}

static unsigned long page_level_size(unsigned int level)
{
	switch (level) {
	case PGTABLE_LEVEL_PMD:
		return PMD_SIZE;
	case PGTABLE_LEVEL_PUD:
		return PUD_SIZE;
	case PGTABLE_LEVEL_P4D:
		return P4D_SIZE;
	default:
		return 0;
	}
}

int arch_should_split_large_page(pte_t *kpte, unsigned long address,
				 struct cpa_data *cpa, unsigned int level,
				 bool nx, bool rw)
{
	unsigned long val = pte_val(ptep_get(kpte));
	unsigned long old_pfn = __page_val_to_pfn(val);
	pgprot_t old_prot = __pgprot(val & ~_PAGE_PFN_MASK);
	unsigned long psize = page_level_size(level);
	unsigned long numpages, lpaddr;
	pgprot_t req_prot;

	if (WARN_ON_ONCE(!psize))
		return -EINVAL;

	/*
	 * Calculate the number of pages, which fit into this large
	 * page starting at address:
	 */
	lpaddr = (address + psize) & ~(psize - 1);
	numpages = (lpaddr - address) >> PAGE_SHIFT;
	if (numpages < cpa->numpages)
		cpa->numpages = numpages;

	req_prot = cpa_pgprot_apply_masks(old_prot, cpa->mask_clr,
					  cpa->mask_set);

	/*
	 * old_pfn points to the large page base pfn, add the offset of the
	 * virtual address within the large page:
	 */
	cpa->pfn = old_pfn + ((address & (psize - 1)) >> PAGE_SHIFT);

	/*
	 * The requested pgprot is the same as the current pgprot, the
	 * large page can be preserved and no update is required.
	 */
	if (pgprot_val(req_prot) == pgprot_val(old_prot))
		return 0;

	/*
	 * If the requested range does not cover the full large page,
	 * split it up.
	 */
	if ((address & (psize - 1)) || cpa->numpages != (psize >> PAGE_SHIFT))
		return 1;

	/* The change covers the entire large page, update it in place */
	req_prot = verify_rwx(old_prot, req_prot, address & ~(psize - 1),
			      old_pfn, psize >> PAGE_SHIFT, nx, rw);
	set_pte(kpte, pfn_pte(old_pfn, req_prot));
	cpa->flags |= CPA_FLUSHTLB;

	return 0;
}

int arch_split_large_page(struct cpa_data *cpa, pte_t *kpte,
			  unsigned long address, unsigned int level,
			  struct ptdesc *ptdesc)
{
	unsigned long val = pte_val(ptep_get(kpte));
	unsigned long pfn = __page_val_to_pfn(val);
	pgprot_t prot = __pgprot(val & ~_PAGE_PFN_MASK);
	pte_t *pbase = ptdesc_address(ptdesc);
	unsigned long pfninc;
	unsigned int i;

	switch (level) {
	case PGTABLE_LEVEL_PMD:
		pfninc = 1;
		break;
	case PGTABLE_LEVEL_PUD:
		pfninc = PMD_SIZE >> PAGE_SHIFT;
		break;
	case PGTABLE_LEVEL_P4D:
		pfninc = PUD_SIZE >> PAGE_SHIFT;
		break;
	default:
		return 1;
	}

	/*
	 * Fill the new page table with leaf entries that have the same
	 * protections as the large page they replace.
	 */
	for (i = 0; i < PTRS_PER_PTE; i++, pfn += pfninc)
		set_pte(pbase + i, pfn_pte(pfn, prot));

	/*
	 * Make sure the filling of the new page table is not reordered
	 * with the store that links it into the page tables, so that a
	 * concurrent hardware table walk does not see a partially filled
	 * table.
	 */
	smp_wmb();

	set_pte(kpte, pfn_pte(page_to_pfn(ptdesc_page(ptdesc)), PAGE_TABLE));

	/*
	 * The split replaces a large mapping that may extend beyond the
	 * requested range, flush the whole TLB.
	 */
	cpa->flags |= CPA_FLUSHTLB;
	cpa->force_flush_all = 1;

	return 0;
}

int arch_cpa_process_fault(struct cpa_data *cpa, unsigned long vaddr,
			   int primary)
{
	cpa->numpages = 1;

	if (!primary)
		return 0;

	/* The linear map is expected to have holes */
	if (is_linear_mapping(vaddr)) {
		cpa->pfn = PFN_DOWN(__pa(vaddr));
		return 0;
	}

	WARN(1, "CPA: called for zero pte. vaddr = %lx cpa->vaddr = %lx\n",
	     vaddr, *cpa->vaddr);

	return -EFAULT;
}

int arch_cpa_process_alias(struct cpa_data *cpa)
{
	unsigned long vaddr = cpa_addr(cpa, cpa->curpage);
	struct cpa_data alias_cpa;
	unsigned long laddr;

	/* The primary target is in the linear map, there is no alias */
	if (is_linear_mapping(vaddr))
		return 0;

	if (!pfn_valid(cpa->pfn))
		return 0;

	laddr = (unsigned long)__va(PFN_PHYS(cpa->pfn));

	alias_cpa = *cpa;
	alias_cpa.vaddr = &laddr;
	alias_cpa.flags &= ~(CPA_PAGES_ARRAY | CPA_ARRAY);
	alias_cpa.curpage = 0;

	/* The linear mapping alias must never be made executable */
	alias_cpa.mask_set.pgprot &= ~_PAGE_EXEC;
	alias_cpa.mask_clr.pgprot &= ~_PAGE_EXEC;

	cpa->force_flush_all = 1;

	return __change_page_attr_set_clr(&alias_cpa, 0);
}

void arch_cpa_flush(struct cpa_data *cpa, int err)
{
	if (err || cpa->force_flush_all ||
	    (cpa->flags & (CPA_ARRAY | CPA_PAGES_ARRAY))) {
		flush_tlb_all();
		return;
	}

	flush_tlb_kernel_range(*cpa->vaddr,
			       *cpa->vaddr + cpa->numpages * PAGE_SIZE);
}

int set_memory_rw_nx(unsigned long addr, int numpages)
{
	return change_page_attr_set_clr(&addr, numpages,
					__pgprot(_PAGE_READ | _PAGE_WRITE),
					__pgprot(_PAGE_EXEC), 0, 0, NULL);
}

int set_memory_ro(unsigned long addr, int numpages)
{
	return change_page_attr_set_clr(&addr, numpages, __pgprot(_PAGE_READ),
					__pgprot(_PAGE_WRITE), 0, 0, NULL);
}

int set_memory_rw(unsigned long addr, int numpages)
{
	return change_page_attr_set(&addr, numpages,
				    __pgprot(_PAGE_READ | _PAGE_WRITE), 0);
}

int set_memory_x(unsigned long addr, int numpages)
{
	return change_page_attr_set(&addr, numpages, __pgprot(_PAGE_EXEC), 0);
}

int set_memory_nx(unsigned long addr, int numpages)
{
	return change_page_attr_clear(&addr, numpages, __pgprot(_PAGE_EXEC), 0);
}

int set_direct_map_invalid(const void *addr, unsigned long numpages)
{
	unsigned long start = (unsigned long)addr;

	return change_page_attr_clear(&start, numpages,
				      __pgprot(_PAGE_PRESENT), 0);
}

int set_direct_map_default(const void *addr, unsigned long numpages)
{
	unsigned long start = (unsigned long)addr;

	return change_page_attr_set_clr(&start, numpages, PAGE_KERNEL,
					__pgprot(_PAGE_EXEC), 0, 0, NULL);
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
	unsigned int level;
	pte_t *pte;

	pte = lookup_address(addr, &level);
	if (!pte)
		return false;

	return pte_present(ptep_get(pte));
}
