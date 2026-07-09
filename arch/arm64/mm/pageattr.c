// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2014, The Linux Foundation. All rights reserved.
 */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mem_encrypt.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>

#include <asm/cacheflush.h>
#include <asm/kfence.h>
#include <asm/mmu.h>
#include <asm/pgtable-prot.h>
#include <asm/set_memory.h>
#include <asm/tlbflush.h>

bool rodata_full __ro_after_init = true;

bool can_set_direct_map(void)
{
	/*
	 * rodata_full, DEBUG_PAGEALLOC and a Realm guest all require linear
	 * map to be mapped at page granularity, so that it is possible to
	 * protect/unprotect single pages.
	 *
	 * KFENCE pool requires page-granular mapping if initialized late.
	 *
	 * Realms need to make pages shared/protected at page granularity.
	 */
	return rodata_full || debug_pagealloc_enabled() ||
		arm64_kfence_can_set_direct_map() || is_realm_world();
}

/*
 * Walk the page tables in @pgd to find the entry mapping @address and report
 * its level in @level.  Present-invalid leaves (PTE_PRESENT_INVALID) are still
 * returned so that set_direct_map_default() can revalidate them.  @nx and @rw
 * are not consumed by the arm64 hooks and are reported as don't-care.
 */
pte_t *lookup_address_in_pgd_attr(pgd_t *pgd, unsigned long address,
				  unsigned int *level, bool *nx, bool *rw)
{
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	*level = PGTABLE_LEVEL_PGD;
	*nx = false;
	*rw = true;

	if (pgd_none(pgdp_get(pgd)))
		return NULL;

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
	return pte_offset_kernel(pmd, address);
}

/*
 * Apply the requested attribute change to a single leaf PTE.  Called by the
 * generic CPA core only for PAGE_SIZE (PTE-level) mappings.  Contiguous PTE
 * groups stay consistent because every member is visited with the same masks.
 */
void arch_change_pte(struct cpa_data *cpa, unsigned long address,
		     pte_t *kpte, pte_t old_pte, bool nx, bool rw)
{
	pteval_t oldval = pte_val(old_pte);
	pteval_t newval;

	/*
	 * Clear first then set: some callers toggle bits which alias each other
	 * (e.g. PTE_NG and PTE_PRESENT_INVALID).
	 */
	newval = (oldval & ~pgprot_val(cpa->mask_clr)) | pgprot_val(cpa->mask_set);

	cpa->pfn = pte_pfn(old_pte);

	if (newval != oldval) {
		__set_pte(kpte, __pte(newval));
		cpa->flags |= CPA_FLUSHTLB;
	}
}

/*
 * Decide what to do with the block mapping at @kpte.  arm64 splits leaf
 * mappings up front (split_kernel_leaf_mapping()), so a block reaching this
 * point is expected to be fully covered by the request and is updated in
 * place.  On-demand splitting is never requested (return 1 is never used).
 */
int arch_should_split_large_page(pte_t *kpte, unsigned long address,
				 struct cpa_data *cpa)
{
	unsigned long numpages, pmask, psize, lpaddr, old_pfn;
	pteval_t oldval, newval;
	unsigned int level;
	bool nx, rw;
	pte_t *tmp;

	tmp = _lookup_address_cpa(cpa, address, &level, &nx, &rw);
	if (tmp != kpte)
		return 1;

	switch (level) {
	case PGTABLE_LEVEL_PMD:
		psize = PMD_SIZE;
		pmask = PMD_MASK;
		old_pfn = pmd_pfn(*(pmd_t *)kpte);
		oldval = pmd_val(*(pmd_t *)kpte);
		break;
	case PGTABLE_LEVEL_PUD:
		psize = PUD_SIZE;
		pmask = PUD_MASK;
		old_pfn = pud_pfn(*(pud_t *)kpte);
		oldval = pud_val(*(pud_t *)kpte);
		break;
	default:
		return -EINVAL;
	}

	/* Number of pages of the request that fit into this large page. */
	lpaddr = (address + psize) & pmask;
	numpages = (lpaddr - address) >> PAGE_SHIFT;
	if (numpages < cpa->numpages)
		cpa->numpages = numpages;

	/* pfn of @address within the large page (used for alias handling). */
	cpa->pfn = old_pfn + ((address & (psize - 1)) >> PAGE_SHIFT);

	/* Base address and 4K-page count of the whole large page. */
	lpaddr = address & pmask;
	numpages = psize >> PAGE_SHIFT;

	newval = (oldval & ~pgprot_val(cpa->mask_clr)) | pgprot_val(cpa->mask_set);

	/* Same attributes: keep the block untouched. */
	if (newval == oldval)
		return 0;

	/*
	 * A block that is only partially covered means the up-front split did
	 * not happen; refuse rather than change neighbouring mappings.
	 */
	if (address != lpaddr || cpa->numpages != numpages) {
		WARN_ON_ONCE(1);
		return -EINVAL;
	}

	if (level == PGTABLE_LEVEL_PMD)
		set_pmd((pmd_t *)kpte, __pmd(newval));
	else
		set_pud((pud_t *)kpte, __pud(newval));
	cpa->flags |= CPA_FLUSHTLB;

	return 0;
}

int arch_split_large_page(struct cpa_data *cpa, pte_t *kpte,
			  unsigned long address, struct ptdesc *ptdesc)
{
	/*
	 * arm64 never splits on demand from the CPA core: leaf mappings are
	 * split up front by split_kernel_leaf_mapping() and any remaining block
	 * is changed in place by arch_should_split_large_page().  Reaching here
	 * is a logic error.
	 */
	WARN_ONCE(1, "CPA: unexpected on-demand split at %lx\n", address);
	return 1;
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
 * Mirror read-only/writable permission changes of a vmalloc mapping onto the
 * linear-map alias of the backing page, matching the direct-map protection
 * provided by rodata_full.  Executable and other changes must not reach the
 * linear alias.
 */
int arch_cpa_process_alias(struct cpa_data *cpa)
{
	struct cpa_data alias_cpa;
	unsigned long laddr, vaddr;
	int ret;

	if (!rodata_full)
		return 0;
	if (!((pgprot_val(cpa->mask_set) | pgprot_val(cpa->mask_clr)) & PTE_RDONLY))
		return 0;

	laddr = (unsigned long)__va(cpa->pfn << PAGE_SHIFT);
	if (!__is_lm_address(laddr))
		return 0;

	/* If the primary mapping already is the linear map there is no alias. */
	vaddr = __cpa_addr(cpa, cpa->curpage);
	if (__is_lm_address(vaddr))
		return 0;

	/* The linear map may use block mappings; isolate the aliased page. */
	ret = split_kernel_leaf_mapping(laddr, laddr + PAGE_SIZE);
	if (WARN_ON_ONCE(ret))
		return ret;

	alias_cpa = *cpa;
	alias_cpa.vaddr = &laddr;
	alias_cpa.flags &= ~(CPA_PAGES_ARRAY | CPA_ARRAY);
	alias_cpa.curpage = 0;

	/* The alias is at a different address; force a full TLB flush. */
	cpa->force_flush_all = 1;

	return __change_page_attr_set_clr(&alias_cpa, 0);
}

void arch_cpa_flush(struct cpa_data *cpa, int err)
{
	unsigned long start;

	/*
	 * Switching a mapping from present-invalid to valid needs no TLB
	 * maintenance: a non-valid entry cannot have been cached.
	 */
	if (!err && !cpa->force_flush_all &&
	    !(cpa->flags & (CPA_ARRAY | CPA_PAGES_ARRAY)) &&
	    pgprot_val(cpa->mask_set) == PTE_PRESENT_VALID_KERNEL &&
	    pgprot_val(cpa->mask_clr) == PTE_PRESENT_INVALID)
		return;

	/*
	 * Flush the whole kernel TLB when the change reached beyond the
	 * requested range (a linear-map alias) or the addresses are not a
	 * single contiguous range; otherwise a ranged flush is enough.
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
	unsigned long size = (unsigned long)numpages << PAGE_SHIFT;
	int ret;

	if (!numpages)
		return 0;

	/*
	 * Split any block or contiguous leaf mapping that straddles the ends of
	 * the range so the generic core only has to change fully-covered
	 * leaves.  The interior keeps its block/contiguous mappings, which are
	 * updated in place.
	 */
	ret = split_kernel_leaf_mapping(addr, addr + size);
	if (WARN_ON_ONCE(ret))
		return ret;

	return change_page_attr_set_clr(&addr, numpages, set_mask, clear_mask,
					0, 0, NULL);
}

int set_memory_ro(unsigned long addr, int numpages)
{
	return __set_memory(addr, numpages,
			    __pgprot(PTE_RDONLY),
			    __pgprot(PTE_WRITE));
}

int set_memory_rw(unsigned long addr, int numpages)
{
	return __set_memory(addr, numpages,
			    __pgprot(PTE_WRITE),
			    __pgprot(PTE_RDONLY));
}

int set_memory_nx(unsigned long addr, int numpages)
{
	return __set_memory(addr, numpages,
			    __pgprot(PTE_PXN),
			    __pgprot(PTE_MAYBE_GP));
}

int set_memory_x(unsigned long addr, int numpages)
{
	return __set_memory(addr, numpages,
			    __pgprot(PTE_MAYBE_GP),
			    __pgprot(PTE_PXN));
}

int set_memory_valid(unsigned long addr, int numpages, int enable)
{
	if (enable)
		return __set_memory(addr, numpages,
				    __pgprot(PTE_PRESENT_VALID_KERNEL),
				    __pgprot(PTE_PRESENT_INVALID));

	return __set_memory(addr, numpages,
			    __pgprot(PTE_PRESENT_INVALID),
			    __pgprot(PTE_PRESENT_VALID_KERNEL));
}

int set_direct_map_invalid(const void *addr, unsigned long numpages)
{
	if (!can_set_direct_map())
		return 0;

	return __set_memory((unsigned long)addr, numpages,
			    __pgprot(PTE_PRESENT_INVALID),
			    __pgprot(PTE_PRESENT_VALID_KERNEL));
}

int set_direct_map_default(const void *addr, unsigned long numpages)
{
	if (!can_set_direct_map())
		return 0;

	return __set_memory((unsigned long)addr, numpages,
			    __pgprot(PTE_PRESENT_VALID_KERNEL | PTE_WRITE),
			    __pgprot(PTE_PRESENT_INVALID | PTE_RDONLY));
}

static int __set_memory_enc_dec(unsigned long addr,
				int numpages,
				bool encrypt)
{
	unsigned long set_prot = 0, clear_prot = 0;
	phys_addr_t start, end;
	int ret;

	if (!is_realm_world())
		return 0;

	if (!__is_lm_address(addr))
		return -EINVAL;

	start = __virt_to_phys(addr);
	end = start + numpages * PAGE_SIZE;

	if (encrypt)
		clear_prot = PROT_NS_SHARED;
	else
		set_prot = PROT_NS_SHARED;

	/*
	 * Break the mapping before we make any changes to avoid stale TLB
	 * entries or Synchronous External Aborts caused by RIPAS_EMPTY
	 */
	ret = __set_memory(addr, numpages,
			   __pgprot(set_prot | PTE_PRESENT_INVALID),
			   __pgprot(clear_prot | PTE_PRESENT_VALID_KERNEL));
	if (ret)
		return ret;

	if (encrypt)
		ret = rsi_set_memory_range_protected(start, end);
	else
		ret = rsi_set_memory_range_shared(start, end);

	if (ret)
		return ret;

	return __set_memory(addr, numpages,
			    __pgprot(PTE_PRESENT_VALID_KERNEL),
			    __pgprot(PTE_PRESENT_INVALID));
}

static int realm_set_memory_encrypted(unsigned long addr, int numpages)
{
	int ret = __set_memory_enc_dec(addr, numpages, true);

	/*
	 * If the request to change state fails, then the only sensible cause
	 * of action for the caller is to leak the memory
	 */
	WARN(ret, "Failed to encrypt memory, %d pages will be leaked",
	     numpages);

	return ret;
}

static int realm_set_memory_decrypted(unsigned long addr, int numpages)
{
	int ret = __set_memory_enc_dec(addr, numpages, false);

	WARN(ret, "Failed to decrypt memory, %d pages will be leaked",
	     numpages);

	return ret;
}

static const struct arm64_mem_crypt_ops realm_crypt_ops = {
	.encrypt = realm_set_memory_encrypted,
	.decrypt = realm_set_memory_decrypted,
};

int realm_register_memory_enc_ops(void)
{
	return arm64_mem_crypt_ops_register(&realm_crypt_ops);
}

#ifdef CONFIG_DEBUG_PAGEALLOC
/*
 * __kernel_map_pages() runs from the page allocator in atomic context, so it
 * cannot go through the generic CPA path (which takes sleeping locks and calls
 * vm_unmap_aliases()).  With DEBUG_PAGEALLOC the linear map is always page
 * mapped, so a plain page-table walk toggling PTE_VALID is sufficient.
 */
static int debug_pagealloc_set_page(pte_t *pte, unsigned long addr, void *data)
{
	int enable = *(int *)data;
	pteval_t val = pte_val(__ptep_get(pte));

	if (enable)
		val = (val & ~PTE_PRESENT_INVALID) | PTE_PRESENT_VALID_KERNEL;
	else
		val = (val & ~PTE_PRESENT_VALID_KERNEL) | PTE_PRESENT_INVALID;

	__set_pte(pte, __pte(val));

	return 0;
}

void __kernel_map_pages(struct page *page, int numpages, int enable)
{
	unsigned long start = (unsigned long)page_address(page);
	unsigned long size = (unsigned long)numpages << PAGE_SHIFT;

	if (!can_set_direct_map())
		return;

	apply_to_existing_page_range(&init_mm, start, size,
				     debug_pagealloc_set_page, &enable);
	flush_tlb_kernel_range(start, start + size);
}
#endif /* CONFIG_DEBUG_PAGEALLOC */

/*
 * This function is used to determine if a linear map page has been marked as
 * not-valid. Walk the page table and check the PTE_VALID bit.
 *
 * Because this is only called on the kernel linear map,  p?d_sect() implies
 * p?d_present(). When debug_pagealloc is enabled, sections mappings are
 * disabled.
 */
bool kernel_page_present(struct page *page)
{
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;
	pte_t *ptep;
	unsigned long addr = (unsigned long)page_address(page);

	pgdp = pgd_offset_k(addr);
	if (pgd_none(READ_ONCE(*pgdp)))
		return false;

	p4dp = p4d_offset(pgdp, addr);
	if (p4d_none(READ_ONCE(*p4dp)))
		return false;

	pudp = pud_offset(p4dp, addr);
	pud = READ_ONCE(*pudp);
	if (pud_none(pud))
		return false;
	if (pud_leaf(pud))
		return pud_valid(pud);

	pmdp = pmd_offset(pudp, addr);
	pmd = READ_ONCE(*pmdp);
	if (pmd_none(pmd))
		return false;
	if (pmd_leaf(pmd))
		return pmd_valid(pmd);

	ptep = pte_offset_kernel(pmdp, addr);
	return pte_valid(__ptep_get(ptep));
}
