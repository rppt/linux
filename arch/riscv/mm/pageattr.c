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
	/*
	 * No arch specific lock is needed: the generic CPA loop already
	 * serializes set_memory() operations with cpa_lock, and unlike x86
	 * (pgd_lock) RISC-V has no concurrent non-CPA writer of the kernel
	 * linear map to serialize the large page split against.
	 */
	.lock = NULL,
};

struct cpa_arch_info *cpa_arch_setup(void)
{
	return &riscv_cpa_info;
}

#ifdef CONFIG_64BIT
static int __split_linear_mapping_pmd(pud_t *pudp,
				      unsigned long vaddr, unsigned long end)
{
	pmd_t *pmdp;
	unsigned long next;

	pmdp = pmd_offset(pudp, vaddr);

	do {
		next = pmd_addr_end(vaddr, end);

		if (next - vaddr >= PMD_SIZE &&
		    vaddr <= (vaddr & PMD_MASK) && end >= next)
			continue;

		if (pmd_leaf(pmdp_get(pmdp))) {
			struct page *pte_page;
			unsigned long pfn = _pmd_pfn(pmdp_get(pmdp));
			pgprot_t prot = __pgprot(pmd_val(pmdp_get(pmdp)) & ~_PAGE_PFN_MASK);
			pte_t *ptep_new;
			int i;

			pte_page = alloc_page(GFP_KERNEL);
			if (!pte_page)
				return -ENOMEM;

			ptep_new = (pte_t *)page_address(pte_page);
			for (i = 0; i < PTRS_PER_PTE; ++i, ++ptep_new)
				set_pte(ptep_new, pfn_pte(pfn + i, prot));

			smp_wmb();

			set_pmd(pmdp, pfn_pmd(page_to_pfn(pte_page), PAGE_TABLE));
		}
	} while (pmdp++, vaddr = next, vaddr != end);

	return 0;
}

static int __split_linear_mapping_pud(p4d_t *p4dp,
				      unsigned long vaddr, unsigned long end)
{
	pud_t *pudp;
	unsigned long next;
	int ret;

	pudp = pud_offset(p4dp, vaddr);

	do {
		next = pud_addr_end(vaddr, end);

		if (next - vaddr >= PUD_SIZE &&
		    vaddr <= (vaddr & PUD_MASK) && end >= next)
			continue;

		if (pud_leaf(pudp_get(pudp))) {
			struct page *pmd_page;
			unsigned long pfn = _pud_pfn(pudp_get(pudp));
			pgprot_t prot = __pgprot(pud_val(pudp_get(pudp)) & ~_PAGE_PFN_MASK);
			pmd_t *pmdp_new;
			int i;

			pmd_page = alloc_page(GFP_KERNEL);
			if (!pmd_page)
				return -ENOMEM;

			pmdp_new = (pmd_t *)page_address(pmd_page);
			for (i = 0; i < PTRS_PER_PMD; ++i, ++pmdp_new)
				set_pmd(pmdp_new,
					pfn_pmd(pfn + ((i * PMD_SIZE) >> PAGE_SHIFT), prot));

			smp_wmb();

			set_pud(pudp, pfn_pud(page_to_pfn(pmd_page), PAGE_TABLE));
		}

		ret = __split_linear_mapping_pmd(pudp, vaddr, next);
		if (ret)
			return ret;
	} while (pudp++, vaddr = next, vaddr != end);

	return 0;
}

static int __split_linear_mapping_p4d(pgd_t *pgdp,
				      unsigned long vaddr, unsigned long end)
{
	p4d_t *p4dp;
	unsigned long next;
	int ret;

	p4dp = p4d_offset(pgdp, vaddr);

	do {
		next = p4d_addr_end(vaddr, end);

		/*
		 * If [vaddr; end] contains [vaddr & P4D_MASK; next], we don't
		 * need to split, we'll change the protections on the whole P4D.
		 */
		if (next - vaddr >= P4D_SIZE &&
		    vaddr <= (vaddr & P4D_MASK) && end >= next)
			continue;

		if (p4d_leaf(p4dp_get(p4dp))) {
			struct page *pud_page;
			unsigned long pfn = _p4d_pfn(p4dp_get(p4dp));
			pgprot_t prot = __pgprot(p4d_val(p4dp_get(p4dp)) & ~_PAGE_PFN_MASK);
			pud_t *pudp_new;
			int i;

			pud_page = alloc_page(GFP_KERNEL);
			if (!pud_page)
				return -ENOMEM;

			/*
			 * Fill the pud level with leaf puds that have the same
			 * protections as the leaf p4d.
			 */
			pudp_new = (pud_t *)page_address(pud_page);
			for (i = 0; i < PTRS_PER_PUD; ++i, ++pudp_new)
				set_pud(pudp_new,
					pfn_pud(pfn + ((i * PUD_SIZE) >> PAGE_SHIFT), prot));

			/*
			 * Make sure the pud filling is not reordered with the
			 * p4d store which could result in seeing a partially
			 * filled pud level.
			 */
			smp_wmb();

			set_p4d(p4dp, pfn_p4d(page_to_pfn(pud_page), PAGE_TABLE));
		}

		ret = __split_linear_mapping_pud(p4dp, vaddr, next);
		if (ret)
			return ret;
	} while (p4dp++, vaddr = next, vaddr != end);

	return 0;
}

static int __split_linear_mapping_pgd(pgd_t *pgdp,
				      unsigned long vaddr,
				      unsigned long end)
{
	unsigned long next;
	int ret;

	do {
		next = pgd_addr_end(vaddr, end);
		/* We never use PGD mappings for the linear mapping */
		ret = __split_linear_mapping_p4d(pgdp, vaddr, next);
		if (ret)
			return ret;
	} while (pgdp++, vaddr = next, vaddr != end);

	return 0;
}

static int split_linear_mapping(unsigned long start, unsigned long end)
{
	return __split_linear_mapping_pgd(pgd_offset_k(start), start, end);
}
#endif	/* CONFIG_64BIT */

int arch_should_split_large_page(pte_t *kpte, unsigned long address,
				 struct cpa_data *cpa, unsigned int level,
				 bool nx, bool rw)
{
	/* Split any large mapping down to the PTE level and update the PTE. */
	return 1;
}

int arch_split_large_page(struct cpa_data *cpa, pte_t *kpte,
			  unsigned long address, unsigned int level,
			  struct ptdesc *ptdesc)
{
	/*
	 * split_linear_mapping() allocates the intermediate tables itself, so
	 * the page table preallocated by the generic code is not used and gets
	 * freed by the caller when a non-zero value is returned.
	 */
#ifdef CONFIG_64BIT
	unsigned long start = address & PAGE_MASK;

	if (!split_linear_mapping(start, start + PAGE_SIZE)) {
		cpa->flags |= CPA_FLUSHTLB;
		cpa->force_flush_all = 1;
	}
#else
	WARN_ON_ONCE(1);
#endif
	return 1;
}

void arch_change_pte(struct cpa_data *cpa, unsigned long address,
		     pte_t *kpte, pte_t old_pte, bool nx, bool rw)
{
	pgprot_t new_prot = __pgprot(pte_val(old_pte) & ~_PAGE_PFN_MASK);
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

	/* The primary target already is the linear map, there is no alias */
	if (is_linear_mapping(vaddr))
		return 0;

	if (!pfn_valid(cpa->pfn))
		return 0;

	laddr = (unsigned long)__va(PFN_PHYS(cpa->pfn));

	alias_cpa = *cpa;
	alias_cpa.vaddr = &laddr;
	alias_cpa.flags &= ~(CPA_PAGES_ARRAY | CPA_ARRAY);
	alias_cpa.curpage = 0;

	/* The linear map alias must never be made executable */
	alias_cpa.mask_set = __pgprot(pgprot_val(alias_cpa.mask_set) & ~_PAGE_EXEC);
	alias_cpa.mask_clr = __pgprot(pgprot_val(alias_cpa.mask_clr) & ~_PAGE_EXEC);

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

int set_direct_map_invalid_noflush(struct page *page)
{
	unsigned long start = (unsigned long)page_address(page);

	return change_page_attr_clear(&start, 1, __pgprot(_PAGE_PRESENT), 0);
}

int set_direct_map_default_noflush(struct page *page)
{
	unsigned long start = (unsigned long)page_address(page);

	return change_page_attr_set_clr(&start, 1, PAGE_KERNEL,
					__pgprot(_PAGE_EXEC), 0, 0, NULL);
}

int set_direct_map_valid_noflush(struct page *page, unsigned nr, bool valid)
{
	unsigned long start = (unsigned long)page_address(page);
	pgprot_t set, clear;

	if (valid) {
		set = PAGE_KERNEL;
		clear = __pgprot(_PAGE_EXEC);
	} else {
		set = __pgprot(0);
		clear = __pgprot(_PAGE_PRESENT);
	}

	return change_page_attr_set_clr(&start, nr, set, clear, 0, 0, NULL);
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
	pte_t *pte = lookup_address(addr, &level);

	if (!pte)
		return false;

	return pte_present(ptep_get(pte));
}
