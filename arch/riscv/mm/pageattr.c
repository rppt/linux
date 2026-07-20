// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2019 SiFive
 */

#include <linux/mm.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/set_memory.h>

int arch_should_split_large_page(struct cpa_data *cpa, struct cpa_split_data *sd)
{
	unsigned long lpaddr, numpages, old_pfn;
	pgprot_t old_prot, new_prot;
	pte_t old;
	int ret;

	ret = cpa_prepare_split(cpa, sd);
	if (ret)
		return ret;

	old = ptep_get(sd->kpte);
	old_prot = __pgprot(pte_val(old) & ~_PAGE_PFN_MASK);
	new_prot = old_prot;
	old_pfn = pte_pfn(old);

	pgprot_val(new_prot) &= ~pgprot_val(cpa->mask_clr);
	pgprot_val(new_prot) |= pgprot_val(cpa->mask_set);

	/*
	 * Record the pfn mapped at @address so the alias check can locate the
	 * matching linear map entry.
	 */
	cpa->pfn = old_pfn + ((sd->address & (sd->psize - 1)) >> PAGE_SHIFT);

	/* If the protections do not change, keep the large page intact. */
	if (pgprot_val(new_prot) == pgprot_val(old_prot))
		return 0;

	/* If the request does not cover the whole large page, split it. */
	lpaddr = sd->address & sd->pmask;
	numpages = sd->psize >> PAGE_SHIFT;
	if (sd->address != lpaddr || cpa->numpages != numpages)
		return 1;

	/* The whole large page is covered: update it in place. */
	set_pte(sd->kpte, pfn_pte(old_pfn, new_prot));
	cpa->flags |= CPA_FLUSHTLB;

	return 0;
}

static void split_set_ptes(pte_t *ptep, unsigned long pfn, unsigned long pfninc,
			   pgprot_t prot)
{
	unsigned int i;

	for (i = 0; i < PTRS_PER_PTE; ++i, ++ptep, pfn += pfninc)
		set_pte(ptep, pfn_pte(pfn, prot));
}

int arch_split_large_page(struct cpa_data *cpa, struct cpa_split_data *sd)
{
#ifdef CONFIG_64BIT
	struct page *base = virt_to_page(sd->pbase);
	unsigned long pfn, pfninc;
	pgprot_t prot;
	pte_t old;
	int ret;

	ret = cpa_revalidate_mapping(cpa, sd);
	if (ret)
		return ret;

	old = ptep_get(sd->kpte);
	prot = __pgprot(pte_val(old) & ~_PAGE_PFN_MASK);
	pfn = pte_pfn(old);

	switch (sd->level) {
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
		return -EINVAL;
	}

	split_set_ptes(sd->pbase, pfn, pfninc, prot);

	smp_wmb();
	set_pte(sd->kpte, pfn_pte(page_to_pfn(base), PAGE_TABLE));

	cpa->flags |= CPA_FLUSHTLB;
	cpa->force_flush_all = 1;

	return 0;
#else
	WARN_ON_ONCE(1);
	return -EINVAL;
#endif
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
	struct cpa_data alias_cpa;
	unsigned long laddr;
	int ret;

	/*
	 * cpa_should_update_alias() only lets non linear map primaries reach
	 * here, so @cpa->pfn always has a linear map alias that must receive
	 * the same protection change.
	 */
	laddr = (unsigned long)__va(PFN_PHYS(cpa->pfn));

	alias_cpa = *cpa;
	alias_cpa.vaddr = &laddr;
	alias_cpa.flags &= ~(CPA_PAGES_ARRAY | CPA_ARRAY | CPA_FLUSHTLB);
	alias_cpa.curpage = 0;
	alias_cpa.force_flush_all = 0;

	/* The linear map alias must never be made executable */
	alias_cpa.mask_set = __pgprot(pgprot_val(alias_cpa.mask_set) & ~_PAGE_EXEC);
	alias_cpa.mask_clr = __pgprot(pgprot_val(alias_cpa.mask_clr) & ~_PAGE_EXEC);

	ret = __change_page_attr_set_clr(&alias_cpa, 0);

	cpa->flags |= alias_cpa.flags & CPA_FLUSHTLB;
	/* Alias changes are outside the primary range, even without a split. */
	cpa->force_flush_all |= alias_cpa.force_flush_all ||
			       (alias_cpa.flags & CPA_FLUSHTLB);

	return ret;
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

#ifdef CONFIG_64BIT
static void flush_new_direct_map(struct cpa_data *cpa)
{
	/* Publish the PTEs before notifying the fault retry path. */
	smp_wmb();
	mark_new_valid_map();
}
#else
static void flush_new_direct_map(struct cpa_data *cpa)
{
	/* RV32 has no fault retry path for the direct map. */
	flush_tlb_kernel_range(*cpa->vaddr,
			       *cpa->vaddr + cpa->numpages * PAGE_SIZE);
}
#endif

static int set_direct_map_noflush(struct cpa_data *cpa)
{
	int ret = __change_page_attr_set_clr(cpa, 1);

	if (!(cpa->flags & CPA_FLUSHTLB))
		return ret;

	/* With alias checks disabled, force_flush_all records a split. */
	if (ret || cpa->force_flush_all)
		flush_tlb_all();
	else if (pgprot_val(cpa->mask_set) & _PAGE_PRESENT)
		flush_new_direct_map(cpa);

	return ret;
}

int set_direct_map_invalid_noflush(struct page *page)
{
	unsigned long start = (unsigned long)page_address(page);
	struct cpa_data cpa = { .vaddr = &start,
				.pgd = NULL,
				.numpages = 1,
				.mask_set = __pgprot(0),
				.mask_clr = __pgprot(_PAGE_PRESENT),
				.flags = CPA_NO_CHECK_ALIAS };

	return set_direct_map_noflush(&cpa);
}

int set_direct_map_default_noflush(struct page *page)
{
	unsigned long start = (unsigned long)page_address(page);
	struct cpa_data cpa = { .vaddr = &start,
				.pgd = NULL,
				.numpages = 1,
				.mask_set = PAGE_KERNEL,
				.mask_clr = __pgprot(_PAGE_EXEC),
				.flags = CPA_NO_CHECK_ALIAS };

	return set_direct_map_noflush(&cpa);
}

int set_direct_map_valid_noflush(struct page *page, unsigned nr, bool valid)
{
	unsigned long start = (unsigned long)page_address(page);
	struct cpa_data cpa = { .vaddr = &start,
				.pgd = NULL,
				.numpages = nr,
				.flags = CPA_NO_CHECK_ALIAS };

	if (valid) {
		cpa.mask_set = PAGE_KERNEL;
		cpa.mask_clr = __pgprot(_PAGE_EXEC);
	} else {
		cpa.mask_set = __pgprot(0);
		cpa.mask_clr = __pgprot(_PAGE_PRESENT);
	}

	return set_direct_map_noflush(&cpa);
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
