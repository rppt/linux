// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2014, The Linux Foundation. All rights reserved.
 */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mem_encrypt.h>
#include <linux/pageattr.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>

#include <asm/cacheflush.h>
#include <asm/cpufeature.h>
#include <asm/pgtable-prot.h>
#include <asm/set_memory.h>
#include <asm/tlbflush.h>
#include <asm/kfence.h>

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

pte_t *lookup_address_in_pgd_attr(pgd_t *pgdp, unsigned long address,
				  unsigned int *level, bool *nx, bool *rw)
{
	pgd_t pgd = pgdp_get(pgdp);
	p4d_t *p4dp, p4d;
	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;

	*level = PGTABLE_LEVEL_PGD;
	*nx = false;
	*rw = true;

	if (pgd_none(pgd))
		return NULL;

	*level = PGTABLE_LEVEL_P4D;
	p4dp = p4d_offset(pgdp, address);
	p4d = p4dp_get(p4dp);
	if (p4d_none(p4d))
		return NULL;

	if (p4d_leaf(p4d))
		return (pte_t *)p4dp;

	*level = PGTABLE_LEVEL_PUD;
	pudp = pud_offset(p4dp, address);
	pud = pudp_get(pudp);
	if (pud_none(pud))
		return NULL;

	if (pud_leaf(pud))
		return (pte_t *)pudp;

	*level = PGTABLE_LEVEL_PMD;
	pmdp = pmd_offset(pudp, address);
	pmd = pmdp_get(pmdp);
	if (pmd_none(pmd))
		return NULL;

	if (pmd_leaf(pmd))
		return (pte_t *)pmdp;

	*level = PGTABLE_LEVEL_PTE;
	return pte_offset_kernel(pmdp, address);
}

static ptval_t set_pageattr_masks(struct cpa_data *cpa, ptval_t val)
{
	/*
	 * Some users clear and set bits which alias each other (e.g. PTE_NG and
	 * PTE_PRESENT_INVALID). It is therefore important that we always clear
	 * first then set.
	 */
	val &= ~pgprot_val(cpa->mask_clr);
	val |= pgprot_val(cpa->mask_set);

	return val;
}

/*
 * A contiguous block must describe the same attributes throughout, so it can
 * only be updated in place when the request covers all of it. @numpages is
 * what is left of the request at @address.
 */
static bool cont_block_covered(struct cpa_data *cpa, unsigned long address,
			       unsigned long numpages, unsigned long size)
{
	unsigned long block = ALIGN_DOWN(address, size);

	/* An array request has no range to compare the block against. */
	if (cpa->req & (CPA_REQ_ARRAY | CPA_REQ_PAGES_ARRAY))
		return false;

	return block >= *cpa->vaddr &&
	       block + size <= address + numpages * PAGE_SIZE;
}

int arch_change_pte(struct cpa_data *cpa, unsigned long address,
		    pte_t *kpte, pte_t old_pte, bool nx, bool rw)
{
	pte_t new_pte = __pte(set_pageattr_masks(cpa, pte_val(old_pte)));

	cpa->pfn = pte_pfn(old_pte);

	if (pte_val(new_pte) == pte_val(old_pte))
		return 0;

	if (pte_cont(old_pte) &&
	    !cont_block_covered(cpa, address, cpa->numpages, CONT_PTE_SIZE)) {
		if (!system_supports_bbml3())
			return -EOPNOTSUPP;

		split_kernel_contpte(kpte);
		new_pte = pte_mknoncont(new_pte);
	}

	__set_pte(kpte, new_pte);
	cpa->state |= CPA_ST_FLUSHTLB;

	return 0;
}

int arch_should_split_large_page(struct cpa_data *cpa, struct cpa_split_data *sd)
{
	unsigned long reqpages = cpa->numpages;
	ptval_t val, new_val;
	int ret;

	ret = cpa_prepare_split(cpa, sd);
	if (ret)
		return ret;

	val = pte_val(__ptep_get(sd->kpte));
	new_val = set_pageattr_masks(cpa, val);

	cpa->pfn = pte_pfn(__pte(val)) +
		   ((sd->address & (sd->psize - 1)) >> PAGE_SHIFT);

	/* If the protections do not change, keep the large page intact. */
	if (new_val == val)
		return 0;

	if (sd->level == PGTABLE_LEVEL_PMD && pmd_cont(__pmd(val)) &&
	    !cont_block_covered(cpa, sd->address, reqpages, CONT_PMD_SIZE)) {
		if (!system_supports_bbml3())
			return -EOPNOTSUPP;

		split_kernel_contpmd((pmd_t *)sd->kpte);
		new_val &= ~PTE_CONT;
	}

	/* If the request does not cover the whole large page, split it. */
	if ((sd->address & ~sd->pmask) ||
	    cpa->numpages != sd->psize >> PAGE_SHIFT) {
		if (!system_supports_bbml3())
			return -EOPNOTSUPP;

		return 1;
	}

	switch (sd->level) {
	case PGTABLE_LEVEL_PMD:
		set_pmd((pmd_t *)sd->kpte, __pmd(new_val));
		break;
	case PGTABLE_LEVEL_PUD:
		set_pud((pud_t *)sd->kpte, __pud(new_val));
		break;
	default:
		return -EINVAL;
	}

	cpa->state |= CPA_ST_FLUSHTLB;

	return 0;
}

int arch_split_large_page(struct cpa_data *cpa, struct cpa_split_data *sd)
{
	int ret;

	ret = cpa_revalidate_mapping(cpa, sd);
	if (ret)
		return ret;

	switch (sd->level) {
	case PGTABLE_LEVEL_PMD:
		split_kernel_pmd((pmd_t *)sd->kpte, pmdp_get((pmd_t *)sd->kpte),
				 sd->pbase, true);
		break;
	case PGTABLE_LEVEL_PUD:
		split_kernel_pud((pud_t *)sd->kpte, pudp_get((pud_t *)sd->kpte),
				 (pmd_t *)sd->pbase, true);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

int arch_cpa_process_fault(struct cpa_data *cpa, unsigned long vaddr)
{
	cpa->numpages = 1;

	if (cpa->state & CPA_ST_ALIAS)
		return 0;

	/* The linear map is expected to have holes */
	if (__is_lm_address(vaddr)) {
		cpa->pfn = __phys_to_pfn(__pa(vaddr));
		return 0;
	}

	WARN(1, "CPA: called for zero pte. vaddr = %lx\n", vaddr);

	return -EFAULT;
}

int arch_cpa_process_alias(struct cpa_data *cpa)
{
	struct cpa_data alias_cpa;
	unsigned long laddr;
	int ret;

	/* Only memory that is part of the linear map has an alias */
	if (!pfn_is_map_memory(cpa->pfn))
		return 0;

	laddr = (unsigned long)__va(PFN_PHYS(cpa->pfn));

	alias_cpa = *cpa;
	alias_cpa.vaddr = &laddr;
	alias_cpa.req &= ~(CPA_REQ_PAGES_ARRAY | CPA_REQ_ARRAY);
	alias_cpa.state &= ~(CPA_ST_FLUSHTLB | CPA_ST_FLUSHTLB_ALL);
	alias_cpa.state |= CPA_ST_ALIAS;
	alias_cpa.curpage = 0;

	/* The linear map alias must never be made executable */
	pgprot_val(alias_cpa.mask_set) &= ~(PTE_PXN | PTE_MAYBE_GP);
	pgprot_val(alias_cpa.mask_clr) &= ~(PTE_PXN | PTE_MAYBE_GP);

	ret = __change_page_attr_set_clr(&alias_cpa);

	cpa->state |= alias_cpa.state & CPA_ST_FLUSHTLB;
	/* Alias changes are outside the primary range, even without a split. */
	if (alias_cpa.state & (CPA_ST_FLUSHTLB | CPA_ST_FLUSHTLB_ALL))
		cpa->state |= CPA_ST_FLUSHTLB_ALL;

	return ret;
}

const struct cpa_op_desc arch_cpa_op_descs[CPA_OP_NUM] = {
	[CPA_SET_RO] = CPA_OP_DESC(PTE_RDONLY, PTE_WRITE, 0),
	[CPA_SET_RW] = CPA_OP_DESC(PTE_WRITE, PTE_RDONLY, 0),
	[CPA_SET_X] = CPA_OP_DESC(0, PTE_PXN, 0),
	[CPA_SET_NX] = CPA_OP_DESC(PTE_PXN, 0, 0),
	[CPA_SET_DEFAULT] = CPA_OP_DESC(PTE_VALID | PTE_WRITE,
					PTE_PRESENT_INVALID | PTE_RDONLY,
					CPA_REQ_NO_ALIAS),
	[CPA_SET_INVALID] = CPA_OP_DESC(PTE_PRESENT_INVALID, PTE_VALID,
					CPA_REQ_NO_ALIAS),
};

int arch_cpa_prepare(struct cpa_data *cpa)
{
	if (!can_set_direct_map() && __is_lm_address(cpa_addr(cpa, 0))) {
		/* The linear map is not mapped at page granularity. */
		cpa->mask_set = __pgprot(0);
		cpa->mask_clr = __pgprot(0);
	} else {
		/*
		 * PTE_MAYBE_GP and PTE_MAYBE_NG depend on capabilities that
		 * are only known at runtime, so they cannot be part of the
		 * static operation table. A kernel mapping is guarded when it
		 * becomes executable and non-global when it becomes valid.
		 */
		if (pgprot_val(cpa->mask_clr) & PTE_PXN)
			pgprot_val(cpa->mask_set) |= PTE_MAYBE_GP;
		if (pgprot_val(cpa->mask_set) & PTE_PXN)
			pgprot_val(cpa->mask_clr) |= PTE_MAYBE_GP;
		if (pgprot_val(cpa->mask_set) & PTE_VALID)
			pgprot_val(cpa->mask_set) |= PTE_MAYBE_NG;
	}

	lazy_mmu_mode_enable();

	return 0;
}

void arch_cpa_finish(struct cpa_data *cpa, int err)
{
	lazy_mmu_mode_disable();

	if (!err && !(cpa->state & CPA_ST_FLUSHTLB))
		return;

	if (err || (cpa->state & CPA_ST_FLUSHTLB_ALL) ||
	    (cpa->req & (CPA_REQ_ARRAY | CPA_REQ_PAGES_ARRAY))) {
		flush_tlb_all();
		return;
	}

	flush_tlb_kernel_range(*cpa->vaddr,
			       *cpa->vaddr + cpa->numpages * PAGE_SIZE);
}

/*
 * The caller flushes the TLB after revoking the direct map and arm64 never
 * caches an entry that is not valid, so only the batch has to be closed.
 */
void arch_cpa_finish_direct_map(struct cpa_data *cpa)
{
	lazy_mmu_mode_disable();
}

/*
 * Change kernel mappings without looking for their aliases. The ranges are
 * always mapped at page granularity, so this never allocates and may be
 * called from atomic context.
 */
static int change_memory_direct(unsigned long addr, int numpages,
				pgprot_t set_mask, pgprot_t clear_mask)
{
	struct cpa_data cpa = {
		.vaddr = &addr,
		.numpages = numpages,
		.mask_set = set_mask,
		.mask_clr = clear_mask,
		.req = CPA_REQ_NO_ALIAS,
	};
	int ret;

	lazy_mmu_mode_enable();
	ret = __change_page_attr_set_clr(&cpa);
	lazy_mmu_mode_disable();

	return ret;
}

int set_memory_valid(unsigned long addr, int numpages, int enable)
{
	pgprot_t set_mask, clear_mask;
	int ret;

	if (enable) {
		set_mask = __pgprot(PTE_PRESENT_VALID_KERNEL);
		clear_mask = __pgprot(PTE_PRESENT_INVALID);
	} else {
		set_mask = __pgprot(PTE_PRESENT_INVALID);
		clear_mask = __pgprot(PTE_PRESENT_VALID_KERNEL);
	}

	ret = change_memory_direct(addr, numpages, set_mask, clear_mask);

	/* An entry that is not valid cannot be cached in the TLB. */
	if (!enable)
		flush_tlb_kernel_range(addr, addr + numpages * PAGE_SIZE);

	return ret;
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
	ret = change_memory_direct(addr, numpages,
				   __pgprot(set_prot | PTE_PRESENT_INVALID),
				   __pgprot(clear_prot | PTE_PRESENT_VALID_KERNEL));
	if (ret)
		return ret;

	flush_tlb_kernel_range(addr, addr + numpages * PAGE_SIZE);

	if (encrypt)
		ret = rsi_set_memory_range_protected(start, end);
	else
		ret = rsi_set_memory_range_shared(start, end);

	if (ret)
		return ret;

	return change_memory_direct(addr, numpages,
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
 */
bool kernel_page_present(struct page *page)
{
	unsigned long addr = (unsigned long)page_address(page);
	unsigned int level;
	bool nx, rw;
	pte_t *ptep;

	ptep = lookup_address_in_pgd_attr(pgd_offset_k(addr), addr, &level,
					  &nx, &rw);
	if (!ptep)
		return false;

	return pte_valid(__ptep_get(ptep));
}
