// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2014, The Linux Foundation. All rights reserved.
 */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mem_encrypt.h>
#include <linux/sched.h>
#include <linux/set_memory.h>
#include <linux/vmalloc.h>

#include <asm/cacheflush.h>
#include <asm/pgtable-prot.h>
#include <asm/set_memory.h>
#include <asm/tlbflush.h>
#include <asm/kfence.h>

/*
 * The affected range is always split to leaf boundaries with
 * split_kernel_leaf_mapping() before entering the CPA loop and the CPA
 * code never splits large pages itself, so there is no need to
 * serialize the loop with cpa_lock. This also allows KFENCE and
 * DEBUG_PAGEALLOC to change memory permissions from atomic context.
 */
static struct cpa_arch_info arm64_cpa_info = {
	.no_cpa_lock = true,
};

struct cpa_arch_info *cpa_arch_setup(void)
{
	return &arm64_cpa_info;
}

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

static unsigned long page_level_size(unsigned int level)
{
	switch (level) {
	case PGTABLE_LEVEL_PMD:
		return PMD_SIZE;
	case PGTABLE_LEVEL_PUD:
		return PUD_SIZE;
	default:
		return 0;
	}
}

static ptval_t set_pageattr_masks(ptval_t val, struct cpa_data *cpa)
{
	/*
	 * Some users clear and set bits which alias each other (e.g. PTE_NG and
	 * PTE_PRESENT_INVALID). It is therefore important that we always clear
	 * first then set.
	 */
	val &= ~(pgprot_val(cpa->mask_clr));
	val |= (pgprot_val(cpa->mask_set));

	return val;
}

int arch_should_split_large_page(pte_t *kpte, unsigned long address,
				 struct cpa_data *cpa, unsigned int level,
				 bool nx, bool rw)
{
	unsigned long psize = page_level_size(level);
	unsigned long numpages, lpaddr;
	ptval_t val, newval;

	if (WARN_ON_ONCE(!psize))
		return -EINVAL;

	val = pte_val(__ptep_get(kpte));

	/*
	 * Calculate the number of pages, which fit into this large
	 * page starting at address:
	 */
	lpaddr = (address + psize) & ~(psize - 1);
	numpages = (lpaddr - address) >> PAGE_SHIFT;
	if (numpages < cpa->numpages)
		cpa->numpages = numpages;

	cpa->pfn = pte_pfn(__pte(val)) + ((address & (psize - 1)) >> PAGE_SHIFT);

	newval = set_pageattr_masks(val, cpa);
	if (newval == val)
		return 0;

	/*
	 * The caller must ensure that the range we are operating on does not
	 * partially overlap a block mapping, or a cont mapping. Any such case
	 * must be eliminated by splitting the mapping with
	 * split_kernel_leaf_mapping() beforehand.
	 */
	if (WARN_ON_ONCE((address & (psize - 1)) ||
			 cpa->numpages != (psize >> PAGE_SHIFT)))
		return -EINVAL;

	switch (level) {
	case PGTABLE_LEVEL_PMD:
		set_pmd((pmd_t *)kpte, __pmd(newval));
		break;
	case PGTABLE_LEVEL_PUD:
		set_pud((pud_t *)kpte, __pud(newval));
		break;
	}

	cpa->flags |= CPA_FLUSHTLB;

	return 0;
}

int arch_split_large_page(struct cpa_data *cpa, pte_t *kpte,
			  unsigned long address, unsigned int level,
			  struct ptdesc *ptdesc)
{
	/*
	 * Live splitting requires break-before-make aware repainting of
	 * contiguous mappings, everything is pre-split with
	 * split_kernel_leaf_mapping() and this should never be reached.
	 */
	WARN_ON_ONCE(1);

	return 1;
}

void arch_change_pte(struct cpa_data *cpa, unsigned long address,
		     pte_t *kpte, pte_t old_pte, bool nx, bool rw)
{
	ptval_t val = pte_val(old_pte);
	ptval_t newval;

	newval = set_pageattr_masks(val, cpa);

	cpa->pfn = pte_pfn(old_pte);

	if (newval != val) {
		__set_pte(kpte, __pte(newval));
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
	if (__is_lm_address(vaddr)) {
		cpa->pfn = PFN_DOWN(__pa(vaddr));
		return 0;
	}

	WARN(1, "CPA: called for zero pte. vaddr = %lx cpa->vaddr = %lx\n",
	     vaddr, *cpa->vaddr);

	return -EFAULT;
}

int arch_cpa_process_alias(struct cpa_data *cpa)
{
	unsigned long size = cpa->numpages * PAGE_SIZE;
	struct cpa_data alias_cpa;
	unsigned long laddr;
	int ret;

	/*
	 * If we are manipulating read-only permissions, apply the same
	 * change to the linear mapping of the pages that back this range.
	 */
	if (!rodata_full)
		return 0;

	if (pgprot_val(cpa->mask_set) != PTE_RDONLY &&
	    pgprot_val(cpa->mask_clr) != PTE_RDONLY)
		return 0;

	/* No alias when the primary target is in the linear map */
	if (__is_lm_address(cpa_addr(cpa, cpa->curpage)))
		return 0;

	if (!pfn_valid(cpa->pfn))
		return 0;

	laddr = (unsigned long)__va(PFN_PHYS(cpa->pfn));

	ret = split_kernel_leaf_mapping(laddr, laddr + size);
	if (WARN_ON_ONCE(ret))
		return ret;

	alias_cpa = *cpa;
	alias_cpa.vaddr = &laddr;
	alias_cpa.flags &= ~(CPA_PAGES_ARRAY | CPA_ARRAY);
	alias_cpa.curpage = 0;

	ret = __change_page_attr_set_clr(&alias_cpa, 0);
	if (ret)
		return ret;

	if (alias_cpa.flags & CPA_FLUSHTLB)
		flush_tlb_kernel_range(laddr, laddr + size);

	return 0;
}

void arch_cpa_flush(struct cpa_data *cpa, int err)
{
	/*
	 * If the memory is being switched from present-invalid to valid
	 * without changing any other bits then a TLBI isn't required as
	 * a non-valid entry cannot be cached in the TLB.
	 */
	if (pgprot_val(cpa->mask_set) == PTE_PRESENT_VALID_KERNEL &&
	    pgprot_val(cpa->mask_clr) == PTE_PRESENT_INVALID)
		return;

	flush_tlb_kernel_range(*cpa->vaddr,
			       *cpa->vaddr + cpa->numpages * PAGE_SIZE);
}

static int update_range_prot(unsigned long start, unsigned long size,
			     pgprot_t set_mask, pgprot_t clear_mask)
{
	struct cpa_data cpa;
	int ret;

	ret = split_kernel_leaf_mapping(start, start + size);
	if (WARN_ON_ONCE(ret))
		return ret;

	memset(&cpa, 0, sizeof(cpa));
	cpa.vaddr = &start;
	cpa.numpages = size >> PAGE_SHIFT;
	cpa.mask_set = set_mask;
	cpa.mask_clr = clear_mask;
	cpa.flags = CPA_NO_CHECK_ALIAS;

	return __change_page_attr_set_clr(&cpa, 1);
}

static int __change_memory_common(unsigned long start, unsigned long size,
				  pgprot_t set_mask, pgprot_t clear_mask)
{
	int ret;

	ret = update_range_prot(start, size, set_mask, clear_mask);

	/*
	 * If the memory is being switched from present-invalid to valid
	 * without changing any other bits then a TLBI isn't required as
	 * a non-valid entry cannot be cached in the TLB.
	 */
	if (pgprot_val(set_mask) != PTE_PRESENT_VALID_KERNEL ||
	    pgprot_val(clear_mask) != PTE_PRESENT_INVALID)
		flush_tlb_kernel_range(start, start + size);
	return ret;
}

static int change_memory_common(unsigned long addr, int numpages,
				pgprot_t set_mask, pgprot_t clear_mask)
{
	unsigned long start = addr;
	unsigned long size = PAGE_SIZE * numpages;
	unsigned long end = start + size;
	struct vm_struct *area;
	int ret;

	if (!PAGE_ALIGNED(addr)) {
		start &= PAGE_MASK;
		end = start + size;
		WARN_ON_ONCE(1);
	}

	/*
	 * Kernel VA mappings are always live, and splitting live section
	 * mappings into page mappings may cause TLB conflicts. This means
	 * we have to ensure that changing the permission bits of the range
	 * we are operating on does not result in such splitting.
	 *
	 * Let's restrict ourselves to mappings created by vmalloc (or vmap).
	 * Disallow VM_ALLOW_HUGE_VMAP mappings to guarantee that only page
	 * mappings are updated and splitting is never needed.
	 *
	 * So check whether the [addr, addr + size) interval is entirely
	 * covered by precisely one VM area that has the VM_ALLOC flag set.
	 */
	area = find_vm_area((void *)addr);
	if (!area ||
	    ((unsigned long)kasan_reset_tag((void *)end) >
	     (unsigned long)kasan_reset_tag(area->addr) + area->size) ||
	    ((area->flags & (VM_ALLOC | VM_ALLOW_HUGE_VMAP)) != VM_ALLOC))
		return -EINVAL;

	if (!numpages)
		return 0;

	ret = split_kernel_leaf_mapping(start, end);
	if (WARN_ON_ONCE(ret))
		return ret;

	return change_page_attr_set_clr(&start, numpages, set_mask, clear_mask,
					0, 0, NULL);
}

int set_memory_ro(unsigned long addr, int numpages)
{
	return change_memory_common(addr, numpages,
					__pgprot(PTE_RDONLY),
					__pgprot(PTE_WRITE));
}

int set_memory_rw(unsigned long addr, int numpages)
{
	return change_memory_common(addr, numpages,
					__pgprot(PTE_WRITE),
					__pgprot(PTE_RDONLY));
}

int set_memory_nx(unsigned long addr, int numpages)
{
	return change_memory_common(addr, numpages,
					__pgprot(PTE_PXN),
					__pgprot(PTE_MAYBE_GP));
}

int set_memory_x(unsigned long addr, int numpages)
{
	return change_memory_common(addr, numpages,
					__pgprot(PTE_MAYBE_GP),
					__pgprot(PTE_PXN));
}

int set_memory_valid(unsigned long addr, int numpages, int enable)
{
	if (enable)
		return __change_memory_common(addr, PAGE_SIZE * numpages,
					__pgprot(PTE_PRESENT_VALID_KERNEL),
					__pgprot(PTE_PRESENT_INVALID));
	else
		return __change_memory_common(addr, PAGE_SIZE * numpages,
					__pgprot(PTE_PRESENT_INVALID),
					__pgprot(PTE_PRESENT_VALID_KERNEL));
}

int set_direct_map_invalid(const void *addr, unsigned long numpages)
{
	pgprot_t clear_mask = __pgprot(PTE_PRESENT_VALID_KERNEL);
	pgprot_t set_mask = __pgprot(PTE_PRESENT_INVALID);

	if (!can_set_direct_map())
		return 0;

	return update_range_prot((unsigned long)addr, PAGE_SIZE * numpages,
				 set_mask, clear_mask);
}

int set_direct_map_default(const void *addr, unsigned long numpages)
{
	pgprot_t set_mask = __pgprot(PTE_PRESENT_VALID_KERNEL | PTE_WRITE);
	pgprot_t clear_mask = __pgprot(PTE_PRESENT_INVALID | PTE_RDONLY);

	if (!can_set_direct_map())
		return 0;

	return update_range_prot((unsigned long)addr, PAGE_SIZE * numpages,
				 set_mask, clear_mask);
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
	ret = __change_memory_common(addr, PAGE_SIZE * numpages,
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

	return __change_memory_common(addr, PAGE_SIZE * numpages,
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
void __kernel_map_pages(struct page *page, int numpages, int enable)
{
	if (!can_set_direct_map())
		return;

	set_memory_valid((unsigned long)page_address(page), numpages, enable);
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
	unsigned long addr = (unsigned long)page_address(page);
	unsigned int level;
	pte_t *pte;

	pte = lookup_address(addr, &level);
	if (!pte)
		return false;

	return pte_valid(__ptep_get(pte));
}
