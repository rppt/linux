// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2014, The Linux Foundation. All rights reserved.
 */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mem_encrypt.h>
#include <linux/sched.h>
#include <linux/pageattr.h>

#include <asm/cacheflush.h>
#include <asm/pgtable-prot.h>
#include <asm/set_memory.h>
#include <asm/tlbflush.h>
#include <asm/kfence.h>

bool rodata_full __ro_after_init = true;

static pte_t cpa_new_pte(struct cpa_data *cpa, pte_t pte)
{
	/*
	 * Some users clear and set bits which alias each other (e.g. PTE_NG and
	 * PTE_PRESENT_INVALID). It is therefore important that we always clear
	 * first then set.
	 */
	pte = clear_pte_bit(pte, cpa->mask_clr);
	return set_pte_bit(pte, cpa->mask_set);
}

static void cpa_set_entry(pte_t *ptep, enum pgtable_level level, pte_t pte)
{
	switch (level) {
	case PGTABLE_LEVEL_PUD:
		set_pud((pud_t *)ptep, __pud(pte_val(pte)));
		break;
	case PGTABLE_LEVEL_PMD:
		set_pmd((pmd_t *)ptep, pte_pmd(pte));
		break;
	default:
		__set_pte(ptep, pte);
		break;
	}
}

static unsigned int cpa_leaf_entries(struct cpa_leaf *leaf)
{
	if (!pte_cont(leaf->pte))
		return 1;

	return leaf->level == PGTABLE_LEVEL_PTE ? CONT_PTES : CONT_PMDS;
}

/*
 * Permission and valid bit changes do not require break-before-make, and the
 * entries of a contiguous group may be updated one by one.
 */
static void cpa_update_leaf(struct cpa_data *cpa, struct cpa_leaf *leaf)
{
	unsigned int i, nr = cpa_leaf_entries(leaf);
	pte_t *ptep = leaf->kpte;

	for (i = 0; i < nr; i++, ptep++)
		cpa_set_entry(ptep, leaf->level,
			      cpa_new_pte(cpa, __ptep_get(ptep)));

	/* Invalid entries are not cached in the TLB */
	if (pte_valid(leaf->pte))
		cpa->state |= CPA_ST_FLUSHTLB;
}

/* A contiguous group is reported as a single leaf */
static pte_t *cpa_set_leaf(struct cpa_leaf *leaf, unsigned long address,
			   pte_t *kpte, enum pgtable_level level,
			   unsigned long psize)
{
	pte_t pte = __ptep_get(kpte);

	if (pte_cont(pte)) {
		unsigned int nr = level == PGTABLE_LEVEL_PTE ? CONT_PTES : CONT_PMDS;

		kpte = PTR_ALIGN_DOWN(kpte, nr * sizeof(*kpte));
		pte = __ptep_get(kpte);
		psize *= nr;
	}

	leaf->address = address;
	leaf->kpte = kpte;
	leaf->pte = pte;
	leaf->pfn = pte_pfn(pte);
	leaf->level = level;
	leaf->psize = psize;

	return kpte;
}

pte_t *arch_cpa_lookup_leaf(struct cpa_data *cpa, unsigned long address,
			    struct cpa_leaf *leaf)
{
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;

	pgdp = pgd_offset_k(address);
	if (pgd_none(pgdp_get(pgdp)))
		return NULL;

	p4dp = p4d_offset(pgdp, address);
	if (p4d_none(p4dp_get(p4dp)))
		return NULL;

	/* pXd_leaf() is true for present-invalid blocks, pXd_sect() is not */
	pudp = pud_offset(p4dp, address);
	pud = pudp_get(pudp);
	if (pud_none(pud))
		return NULL;
	if (pud_leaf(pud))
		return cpa_set_leaf(leaf, address, (pte_t *)pudp,
				    PGTABLE_LEVEL_PUD, PUD_SIZE);

	pmdp = pmd_offset(pudp, address);
	pmd = pmdp_get(pmdp);
	if (pmd_none(pmd))
		return NULL;
	if (pmd_leaf(pmd))
		return cpa_set_leaf(leaf, address, (pte_t *)pmdp,
				    PGTABLE_LEVEL_PMD, PMD_SIZE);

	return cpa_set_leaf(leaf, address, pte_offset_kernel(pmdp, address),
			    PGTABLE_LEVEL_PTE, PAGE_SIZE);
}

int arch_cpa_should_split_large_page(struct cpa_data *cpa,
				     struct cpa_leaf *leaf)
{
	unsigned long lpaddr = ALIGN_DOWN(leaf->address, leaf->psize);
	unsigned long numpages = leaf->psize >> PAGE_SHIFT;

	if (cpa->req & CPA_REQ_SPLIT)
		return arm64_cpa_prepare_split(leaf);

	if (pte_val(cpa_new_pte(cpa, leaf->pte)) == pte_val(leaf->pte))
		return 0;

	if (leaf->address != lpaddr || cpa->numpages < numpages)
		return arm64_cpa_prepare_split(leaf);

	cpa_update_leaf(cpa, leaf);

	return 0;
}

void arch_cpa_change_pte(struct cpa_data *cpa, struct cpa_leaf *leaf)
{
	cpa->pfn = leaf->pfn;

	if (pte_val(cpa_new_pte(cpa, leaf->pte)) != pte_val(leaf->pte))
		cpa_update_leaf(cpa, leaf);

	cpa->numpages = 1;
}

int arch_cpa_process_fault(struct cpa_data *cpa, unsigned long vaddr)
{
	/* The linear map has holes, skip them */
	if ((cpa->state & CPA_ST_ALIAS) || __is_lm_address(__tag_reset(vaddr))) {
		cpa->numpages = 1;
		return 0;
	}

	WARN(1, "CPA: called for zero pte. vaddr = %lx cpa->vaddr = %lx\n",
	     vaddr, cpa->vaddr);
	return -EFAULT;
}

/*
 * With rodata=full the write permissions of the linear alias follow the
 * permissions of other mappings of the same memory.
 */
int arch_cpa_process_alias(struct cpa_data *cpa)
{
	unsigned long laddr = (unsigned long)pfn_to_kaddr(cpa->pfn);

	if (!rodata_full ||
	    __is_lm_address(__tag_reset(cpa_addr(cpa, cpa->curpage))) ||
	    !pfn_valid(cpa->pfn))
		return 0;

	/* Only write permissions are propagated to the linear alias */
	return cpa_change_alias(cpa, laddr,
				__pgprot(~(PTE_RDONLY | PTE_WRITE)));
}

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

int set_memory_ro(unsigned long addr, int numpages)
{
	return cpa_set_clr(addr, numpages, __pgprot(PTE_RDONLY),
			   __pgprot(PTE_WRITE), 0, NULL);
}

int set_memory_rw(unsigned long addr, int numpages)
{
	return cpa_set_clr(addr, numpages, __pgprot(PTE_WRITE),
			   __pgprot(PTE_RDONLY), 0, NULL);
}

int set_memory_nx(unsigned long addr, int numpages)
{
	return cpa_set_clr(addr, numpages, __pgprot(PTE_PXN),
			   __pgprot(PTE_MAYBE_GP), 0, NULL);
}

int set_memory_x(unsigned long addr, int numpages)
{
	return cpa_set_clr(addr, numpages, __pgprot(PTE_MAYBE_GP),
			   __pgprot(PTE_PXN), 0, NULL);
}

int set_memory_valid(unsigned long addr, int numpages, int enable)
{
	if (enable)
		return cpa_set_clr(addr, numpages,
				   __pgprot(PTE_PRESENT_VALID_KERNEL),
				   __pgprot(PTE_PRESENT_INVALID),
				   CPA_REQ_NO_ALIAS, NULL);

	return cpa_set_clr(addr, numpages, __pgprot(PTE_PRESENT_INVALID),
			   __pgprot(PTE_PRESENT_VALID_KERNEL),
			   CPA_REQ_NO_ALIAS, NULL);
}

int set_direct_map_invalid_noflush(struct page *page, unsigned int numpages)
{
	pgprot_t clear_mask = __pgprot(PTE_PRESENT_VALID_KERNEL);
	pgprot_t set_mask = __pgprot(PTE_PRESENT_INVALID);

	if (!can_set_direct_map())
		return 0;

	return cpa_change_direct_map(page, numpages, set_mask, clear_mask);
}

int set_direct_map_default_noflush(struct page *page, unsigned int numpages)
{
	pgprot_t set_mask = __pgprot(PTE_PRESENT_VALID_KERNEL | PTE_WRITE);
	pgprot_t clear_mask = __pgprot(PTE_PRESENT_INVALID | PTE_RDONLY);

	if (!can_set_direct_map())
		return 0;

	return cpa_change_direct_map(page, numpages, set_mask, clear_mask);
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
	ret = cpa_set_clr(addr, numpages,
			  __pgprot(set_prot | PTE_PRESENT_INVALID),
			  __pgprot(clear_prot | PTE_PRESENT_VALID_KERNEL),
			  CPA_REQ_NO_ALIAS, NULL);

	if (ret)
		return ret;

	if (encrypt)
		ret = rsi_set_memory_range_protected(start, end);
	else
		ret = rsi_set_memory_range_shared(start, end);

	if (ret)
		return ret;

	return cpa_set_clr(addr, numpages, __pgprot(PTE_PRESENT_VALID_KERNEL),
			   __pgprot(PTE_PRESENT_INVALID), CPA_REQ_NO_ALIAS, NULL);
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
static int debug_pagealloc_set_pte(pte_t *ptep, unsigned long addr, void *data)
{
	pte_t pte = __ptep_get(ptep);

	if (*(int *)data)
		__set_pte(ptep, pte_mkvalid_k(pte));
	else
		__set_pte(ptep, pte_mkinvalid(pte));

	return 0;
}

/*
 * DEBUG_PAGEALLOC forces base page mappings of the linear map, so there is
 * nothing to split and the PTEs can be updated from any context.
 */
void __kernel_map_pages(struct page *page, int numpages, int enable)
{
	unsigned long addr = (unsigned long)page_address(page);
	unsigned long size = PAGE_SIZE * numpages;

	if (!can_set_direct_map())
		return;

	apply_to_existing_page_range(&init_mm, addr, size,
				     debug_pagealloc_set_pte, &enable);

	/* Invalid entries are not cached in the TLB */
	if (!enable)
		flush_tlb_kernel_range(addr, addr + size);
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
