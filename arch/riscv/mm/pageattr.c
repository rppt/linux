// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2019 SiFive
 */

#include <linux/mm.h>
#include <linux/pagewalk.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>
#include <linux/vmalloc.h>
#include <asm/tlbflush.h>
#include <asm/bitops.h>

#ifndef CONFIG_GENERIC_SET_MEMORY
struct pageattr_masks {
	pgprot_t set_mask;
	pgprot_t clear_mask;
};

static unsigned long set_pageattr_masks(unsigned long val, struct mm_walk *walk)
{
	struct pageattr_masks *masks = walk->private;
	unsigned long new_val = val;

	new_val &= ~(pgprot_val(masks->clear_mask));
	new_val |= (pgprot_val(masks->set_mask));

	return new_val;
}

static int pageattr_p4d_entry(p4d_t *p4d, unsigned long addr,
			      unsigned long next, struct mm_walk *walk)
{
	p4d_t val = p4dp_get(p4d);

	if (p4d_leaf(val)) {
		val = __p4d(set_pageattr_masks(p4d_val(val), walk));
		set_p4d(p4d, val);
	}

	return 0;
}

static int pageattr_pud_entry(pud_t *pud, unsigned long addr,
			      unsigned long next, struct mm_walk *walk)
{
	pud_t val = pudp_get(pud);

	if (pud_leaf(val)) {
		val = __pud(set_pageattr_masks(pud_val(val), walk));
		set_pud(pud, val);
	}

	return 0;
}

static int pageattr_pmd_entry(pmd_t *pmd, unsigned long addr,
			      unsigned long next, struct mm_walk *walk)
{
	pmd_t val = pmdp_get(pmd);

	if (pmd_leaf(val)) {
		val = __pmd(set_pageattr_masks(pmd_val(val), walk));
		set_pmd(pmd, val);
	}

	return 0;
}

static int pageattr_pte_entry(pte_t *pte, unsigned long addr,
			      unsigned long next, struct mm_walk *walk)
{
	pte_t val = ptep_get(pte);

	val = __pte(set_pageattr_masks(pte_val(val), walk));
	set_pte(pte, val);

	return 0;
}

static int pageattr_pte_hole(unsigned long addr, unsigned long next,
			     int depth, struct mm_walk *walk)
{
	/* Nothing to do here */
	return 0;
}

static const struct mm_walk_ops pageattr_ops = {
	.p4d_entry = pageattr_p4d_entry,
	.pud_entry = pageattr_pud_entry,
	.pmd_entry = pageattr_pmd_entry,
	.pte_entry = pageattr_pte_entry,
	.pte_hole = pageattr_pte_hole,
	.walk_lock = PGWALK_RDLOCK,
};

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

static int __set_memory(unsigned long addr, int numpages, pgprot_t set_mask,
			pgprot_t clear_mask)
{
	int ret;
	unsigned long start = addr;
	unsigned long end = start + PAGE_SIZE * numpages;
	unsigned long __maybe_unused lm_start;
	unsigned long __maybe_unused lm_end;
	struct pageattr_masks masks = {
		.set_mask = set_mask,
		.clear_mask = clear_mask
	};

	if (!numpages)
		return 0;

	mmap_write_lock(&init_mm);

#ifdef CONFIG_64BIT
	/*
	 * We are about to change the permissions of a kernel mapping, we must
	 * apply the same changes to its linear mapping alias, which may imply
	 * splitting a huge mapping.
	 */

	if (is_vmalloc_or_module_addr((void *)start)) {
		struct vm_struct *area = NULL;
		int i, page_start;

		area = find_vm_area((void *)start);
		page_start = (start - (unsigned long)area->addr) >> PAGE_SHIFT;

		for (i = page_start; i < page_start + numpages; ++i) {
			lm_start = (unsigned long)page_address(area->pages[i]);
			lm_end = lm_start + PAGE_SIZE;

			ret = split_linear_mapping(lm_start, lm_end);
			if (ret)
				goto unlock;

			ret = walk_kernel_page_table_range(lm_start, lm_end,
						    &pageattr_ops, NULL, &masks);
			if (ret)
				goto unlock;
		}
	} else if (is_kernel_mapping(start) || is_linear_mapping(start)) {
		if (is_kernel_mapping(start)) {
			lm_start = (unsigned long)lm_alias(start);
			lm_end = (unsigned long)lm_alias(end);
		} else {
			lm_start = start;
			lm_end = end;
		}

		ret = split_linear_mapping(lm_start, lm_end);
		if (ret)
			goto unlock;

		ret = walk_kernel_page_table_range(lm_start, lm_end,
					    &pageattr_ops, NULL, &masks);
		if (ret)
			goto unlock;
	}

	ret =  walk_kernel_page_table_range(start, end, &pageattr_ops, NULL,
				     &masks);

unlock:
	mmap_write_unlock(&init_mm);

	/*
	 * We can't use flush_tlb_kernel_range() here as we may have split a
	 * hugepage that is larger than that, so let's flush everything.
	 */
	flush_tlb_all();
#else
	ret =  walk_kernel_page_table_range(start, end, &pageattr_ops, NULL,
				     &masks);

	mmap_write_unlock(&init_mm);

	flush_tlb_kernel_range(start, end);
#endif

	return ret;
}

#else /* CONFIG_GENERIC_SET_MEMORY */

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
	unsigned long numpages, pmask, psize, lpaddr, old_pfn;
	pgprot_t old_prot, req_prot;
	unsigned int level;
	bool nx, rw;
	pte_t *tmp;

	tmp = _lookup_address_cpa(cpa, address, &level, &nx, &rw);
	if (tmp != kpte)
		return 1;

	switch (level) {
	case PGTABLE_LEVEL_PMD:
		old_prot = pmd_pgprot(*(pmd_t *)kpte);
		old_pfn = _pmd_pfn(*(pmd_t *)kpte);
		psize = PMD_SIZE;
		pmask = PMD_MASK;
		break;
	case PGTABLE_LEVEL_PUD:
		old_prot = pud_pgprot(*(pud_t *)kpte);
		old_pfn = _pud_pfn(*(pud_t *)kpte);
		psize = PUD_SIZE;
		pmask = PUD_MASK;
		break;
	default:
		return -EINVAL;
	}

	/* Number of pages of the request that fit into this large page. */
	lpaddr = (address + psize) & pmask;
	numpages = (lpaddr - address) >> PAGE_SHIFT;
	if (numpages < cpa->numpages)
		cpa->numpages = numpages;

	req_prot = old_prot;
	pgprot_val(req_prot) &= ~pgprot_val(cpa->mask_clr);
	pgprot_val(req_prot) |= pgprot_val(cpa->mask_set);

	/* pfn of @address within the large page (used for alias handling). */
	cpa->pfn = old_pfn + ((address & (psize - 1)) >> PAGE_SHIFT);

	/* Base address and 4K-page count of the whole large page. */
	lpaddr = address & pmask;
	numpages = psize >> PAGE_SHIFT;

	/* Same protection: nothing to do, keep the large page. */
	if (pgprot_val(req_prot) == pgprot_val(old_prot))
		return 0;

	/* Request does not cover the whole large page: split it. */
	if (address != lpaddr || cpa->numpages != numpages)
		return 1;

	/* Whole large page covered: update the leaf in place. */
	if (level == PGTABLE_LEVEL_PMD)
		set_pmd((pmd_t *)kpte, pfn_pmd(old_pfn, req_prot));
	else
		set_pud((pud_t *)kpte, pfn_pud(old_pfn, req_prot));
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
	unsigned long old_pfn, i;
	unsigned int level;
	pgprot_t prot;
	bool nx, rw;
	pte_t *tmp;

	tmp = _lookup_address_cpa(cpa, address, &level, &nx, &rw);
	if (tmp != kpte)
		return 1;

	switch (level) {
	case PGTABLE_LEVEL_PMD: {
		pte_t *pbase = (pte_t *)page_address(base);

		old_pfn = _pmd_pfn(*(pmd_t *)kpte);
		prot = pmd_pgprot(*(pmd_t *)kpte);
		for (i = 0; i < PTRS_PER_PTE; i++)
			set_pte(pbase + i, pfn_pte(old_pfn + i, prot));
		smp_wmb();
		set_pmd((pmd_t *)kpte, pfn_pmd(page_to_pfn(base), PAGE_TABLE));
		break;
	}
	case PGTABLE_LEVEL_PUD: {
		pmd_t *pbase = (pmd_t *)page_address(base);

		old_pfn = _pud_pfn(*(pud_t *)kpte);
		prot = pud_pgprot(*(pud_t *)kpte);
		for (i = 0; i < PTRS_PER_PMD; i++)
			set_pmd(pbase + i,
				pfn_pmd(old_pfn + ((i * PMD_SIZE) >> PAGE_SHIFT),
					prot));
		smp_wmb();
		set_pud((pud_t *)kpte, pfn_pud(page_to_pfn(base), PAGE_TABLE));
		break;
	}
	default:
		return 1;
	}

	/*
	 * A split may affect a mapping larger than the requested range, so
	 * flush everything before the attribute change touches the new leaves.
	 */
	flush_tlb_all();

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
 * RISC-V updates the linear-map alias in __set_memory() below and always
 * passes CPA_NO_CHECK_ALIAS, so this hook is never invoked; it exists only to
 * satisfy the generic core.
 */
int arch_cpa_process_alias(struct cpa_data *cpa)
{
	return 0;
}

void arch_cpa_flush(struct cpa_data *cpa, int err)
{
	/*
	 * A split may have affected a range larger than the request, so flush
	 * the whole kernel TLB (matching the pre-CPA behaviour on 64-bit).
	 */
	flush_tlb_all();
}

static int __set_memory(unsigned long addr, int numpages, pgprot_t set_mask,
			pgprot_t clear_mask)
{
	unsigned long start = addr;
	int ret;

	if (!numpages)
		return 0;

#ifdef CONFIG_64BIT
	/*
	 * Apply the same change to the linear-mapping alias of the range: the
	 * permissions of a kernel or vmalloc mapping and those of its linear
	 * alias must be kept in sync.
	 */
	if (is_vmalloc_or_module_addr((void *)start)) {
		struct vm_struct *area = find_vm_area((void *)start);
		int i, page_start;

		page_start = (start - (unsigned long)area->addr) >> PAGE_SHIFT;

		for (i = page_start; i < page_start + numpages; ++i) {
			unsigned long lm =
				(unsigned long)page_address(area->pages[i]);

			ret = change_page_attr_set_clr(&lm, 1, set_mask,
						       clear_mask, 0,
						       CPA_NO_CHECK_ALIAS, NULL);
			if (ret)
				return ret;
		}
	} else if (is_kernel_mapping(start)) {
		unsigned long lm = (unsigned long)lm_alias(start);

		ret = change_page_attr_set_clr(&lm, numpages, set_mask,
					       clear_mask, 0,
					       CPA_NO_CHECK_ALIAS, NULL);
		if (ret)
			return ret;
	}
#endif

	return change_page_attr_set_clr(&start, numpages, set_mask, clear_mask,
					0, CPA_NO_CHECK_ALIAS, NULL);
}

#endif /* CONFIG_GENERIC_SET_MEMORY */

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
