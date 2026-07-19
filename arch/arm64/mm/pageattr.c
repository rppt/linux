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

static struct cpa_arch_info arm64_cpa_info = {
	/*
	 * No arch specific lock is needed: the generic CPA loop serializes
	 * set_memory() with cpa_lock, which also covers the large page split.
	 * arm64 relies on BBML2 to change live block mappings without TLB
	 * conflicts, so no break-before-make serialization is required either.
	 */
	.lock = NULL,
};

struct cpa_arch_info *cpa_arch_setup(void)
{
	return &arm64_cpa_info;
}

int arch_should_split_large_page(struct cpa_data *cpa, struct cpa_split_data *sd)
{
	pte_t *kpte = sd->kpte;
	unsigned long old_pfn, lpaddr, numpages;
	pteval_t oldval, newval;
	bool cont;

	switch (sd->level) {
	case PGTABLE_LEVEL_PTE:
		/*
		 * Only contiguous PTEs are routed here (see arch_cont_pte());
		 * they must be broken apart before a single page can change.
		 */
		cpa->pfn = pte_pfn(__ptep_get(kpte));
		return 1;
	case PGTABLE_LEVEL_PMD: {
		pmd_t pmd = pmdp_get((pmd_t *)kpte);

		oldval = pmd_val(pmd);
		old_pfn = pmd_pfn(pmd);
		cont = pmd_cont(pmd);
		break;
	}
	case PGTABLE_LEVEL_PUD: {
		pud_t pud = pudp_get((pud_t *)kpte);

		oldval = pud_val(pud);
		old_pfn = pud_pfn(pud);
		cont = false;			/* arm64 has no contiguous PUDs */
		break;
	}
	default:
		return -EINVAL;
	}

	/*
	 * Record the pfn mapped at sd->address so the alias check can locate
	 * the matching linear map entry.
	 */
	cpa->pfn = old_pfn + ((sd->address & (sd->psize - 1)) >> PAGE_SHIFT);

	/*
	 * A contiguous block maps its span as a unit, so it has to be split
	 * into ordinary blocks before any single entry can change.
	 */
	if (cont)
		return 1;

	/*
	 * The permission masks are in PTE format; arm64 uses the same bit
	 * positions at every level, so they apply directly to the block entry.
	 */
	newval = oldval;
	newval &= ~pgprot_val(cpa->mask_clr);
	newval |= pgprot_val(cpa->mask_set);

	/* If the protections do not change, keep the large mapping. */
	if (newval == oldval)
		return 0;

	/* If the request does not cover the whole mapping, split it. */
	lpaddr = sd->address & sd->pmask;
	numpages = sd->psize >> PAGE_SHIFT;
	if (sd->address != lpaddr || cpa->numpages != numpages)
		return 1;

	/* The whole mapping is covered: update it in place. */
	if (sd->level == PGTABLE_LEVEL_PMD)
		set_pmd((pmd_t *)kpte, __pmd(newval));
	else
		set_pud((pud_t *)kpte, __pud(newval));
	cpa->flags |= CPA_FLUSHTLB;

	return 0;
}

int arch_split_large_page(struct cpa_data *cpa, struct cpa_split_data *sd)
{
	int ret;

	/*
	 * Split one level of the large mapping using the page table the core
	 * preallocated.  On BBML2 the freshly installed table can go live
	 * without break-before-make, and the range flush at the end of the CPA
	 * operation evicts the stale large TLB entry for the page that changes.
	 */
	ret = split_kernel_leaf_pgtable(sd->kpte, sd->level, sd->ptdesc);
	cpa->flags |= CPA_FLUSHTLB;

	return ret;
}

void arch_change_pte(struct cpa_data *cpa, unsigned long address,
		     pte_t *kpte, pte_t old_pte, bool nx, bool rw)
{
	pteval_t val;
	pte_t new_pte;

	cpa->pfn = pte_pfn(old_pte);

	/*
	 * Contiguous PTEs are reported by arch_cont_pte() and broken up through
	 * the split path before reaching this point, so the entry is always an
	 * ordinary page here.  Some bits alias each other (e.g. PTE_NG and
	 * PTE_PRESENT_INVALID), so always clear before setting.
	 */
	val = pte_val(old_pte);
	val &= ~pgprot_val(cpa->mask_clr);
	val |= pgprot_val(cpa->mask_set);
	new_pte = __pte(val);

	if (pte_val(new_pte) != pte_val(old_pte)) {
		__set_pte(kpte, new_pte);
		cpa->flags |= CPA_FLUSHTLB;
	}
}

int arch_cpa_process_fault(struct cpa_data *cpa, unsigned long vaddr,
			   int primary)
{
	cpa->numpages = 1;

	if (!primary)
		return 0;

	/* The linear map is expected to have holes when it is page-mapped */
	if (__is_lm_address(vaddr)) {
		cpa->pfn = __phys_to_pfn(__pa(vaddr));
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

	/*
	 * Only read-only permission changes are mirrored into the linear map,
	 * and only when it is mapped at page granularity (rodata_full).  Making
	 * a vmalloc mapping read-only must also drop write access from its
	 * linear alias, but executability and validity changes must not touch
	 * the alias.
	 */
	if (!rodata_full ||
	    (pgprot_val(cpa->mask_set) != PTE_RDONLY &&
	     pgprot_val(cpa->mask_clr) != PTE_RDONLY))
		return 0;

	laddr = (unsigned long)__va(PFN_PHYS(cpa->pfn));

	alias_cpa = *cpa;
	alias_cpa.vaddr = &laddr;
	alias_cpa.flags &= ~(CPA_PAGES_ARRAY | CPA_ARRAY);
	alias_cpa.curpage = 0;

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

/*
 * Change the permissions of a kernel mapping through the generic CPA core
 * without the vmalloc-area restrictions imposed on set_memory_*().  This is
 * used for the linear map (set_direct_map*(), encryption state changes), where
 * there is no vmalloc alias to search and where the caller may be atomic, so
 * the vm_unmap_aliases() done by change_page_attr_set_clr() must be avoided.
 */
static int __change_memory_common(unsigned long start, unsigned long size,
				  pgprot_t set_mask, pgprot_t clear_mask)
{
	struct cpa_data cpa = {
		.vaddr = &start,
		.numpages = size >> PAGE_SHIFT,
		.mask_set = set_mask,
		.mask_clr = clear_mask,
		.flags = CPA_NO_CHECK_ALIAS,
	};
	int ret;

	ret = __change_page_attr_set_clr(&cpa, 1);

	if (cpa.flags & CPA_FLUSHTLB)
		arch_cpa_flush(&cpa, ret);

	return ret;
}

static int change_memory_common(unsigned long addr, int numpages,
				pgprot_t set_mask, pgprot_t clear_mask)
{
	unsigned long start = addr;
	unsigned long size = PAGE_SIZE * numpages;
	unsigned long end = start + size;
	struct vm_struct *area;

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

	/*
	 * Apply the change through the generic CPA core.  It updates the
	 * vmalloc mapping in place and, for read-only changes under
	 * rodata_full, mirrors it into the linear alias via
	 * arch_cpa_process_alias().
	 */
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

int set_direct_map_invalid_noflush(struct page *page)
{
	if (!can_set_direct_map())
		return 0;

	return __change_memory_common((unsigned long)page_address(page),
				      PAGE_SIZE,
				      __pgprot(PTE_PRESENT_INVALID),
				      __pgprot(PTE_PRESENT_VALID_KERNEL));
}

int set_direct_map_default_noflush(struct page *page)
{
	if (!can_set_direct_map())
		return 0;

	return __change_memory_common((unsigned long)page_address(page),
				      PAGE_SIZE,
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

int set_direct_map_valid_noflush(struct page *page, unsigned nr, bool valid)
{
	unsigned long addr = (unsigned long)page_address(page);

	if (!can_set_direct_map())
		return 0;

	return set_memory_valid(addr, nr, valid);
}

#ifdef CONFIG_DEBUG_PAGEALLOC
/*
 * This is - apart from the return value - doing the same
 * thing as the new set_direct_map_valid_noflush() function.
 *
 * Unify? Explain the conceptual differences?
 */
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
