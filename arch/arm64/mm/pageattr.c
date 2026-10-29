// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2014, The Linux Foundation. All rights reserved.
 */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mem_encrypt.h>
#include <linux/pageattr.h>
#include <linux/set_memory.h>
#include <linux/vmalloc.h>

#include <asm/cacheflush.h>
#include <asm/pgtable-prot.h>
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

/* bit 1 of a leaf entry is set in pages and clear in blocks */
#define CPA_PAGE_BIT	(PTE_TYPE_PAGE & ~PTE_VALID)

/*
 * The protections in arch_cpa_prot_ops[] and in struct cpa_leaf do not
 * depend on the runtime configuration:
 * - nG of valid entries is not included, it depends on KPTI and the same
 *   bit marks present invalid entries;
 * - GP is set in executable entries when the kernel does not use BTI.
 */
struct cpa_prot_op arch_cpa_prot_ops[CPA_PROT_NR] __ro_after_init = {
	[CPA_PROT_RO] = {
		.set = __pgprot(PTE_RDONLY),
		.clr = __pgprot(PTE_WRITE),
		.alias = true,
	},
	[CPA_PROT_RW] = {
		.set = __pgprot(PTE_WRITE),
		.clr = __pgprot(PTE_RDONLY),
		.alias = true,
	},
	[CPA_PROT_X] = {
		.set = __pgprot(PTE_GP),
		.clr = __pgprot(PTE_PXN),
	},
	[CPA_PROT_NX] = {
		.set = __pgprot(PTE_PXN),
		.clr = __pgprot(PTE_GP),
	},
	[CPA_PROT_NP] = {
		.set = __pgprot(PTE_PRESENT_INVALID),
		.clr = __pgprot(PTE_VALID),
	},
	[CPA_PROT_P] = {
		.set = __pgprot(PTE_VALID),
		.clr = __pgprot(PTE_PRESENT_INVALID),
	},
	[CPA_PROT_INVALID] = {
		.set = __pgprot(PTE_PRESENT_INVALID),
		.clr = __pgprot(PTE_VALID),
	},
	[CPA_PROT_DEFAULT] = {
		.set = __pgprot(PTE_VALID | PTE_WRITE),
		.clr = __pgprot(PTE_PRESENT_INVALID | PTE_RDONLY),
	},
};

int arch_cpa_check(struct cpa_req *req)
{
	unsigned long start = req->addr;
	unsigned long end = start + req->numpages * PAGE_SIZE;
	struct vm_struct *area;

	/* rodata=noalias leaves the linear map writable */
	if (!rodata_full)
		req->flags |= CPA_NO_ALIAS;

	/* the linear map is never executable */
	if (__is_lm_address(start) && __is_lm_address(end - 1))
		return pgprot_val(req->clr) & PTE_PXN ? -EINVAL : 0;

	/*
	 * Splitting vmalloc leaves needs BBML3, allow only areas that are
	 * mapped with base pages.
	 */
	area = find_vm_area((void *)start);
	if (!area)
		return -EINVAL;
	if (end > (unsigned long)kasan_reset_tag(area->addr) + area->size)
		return -EINVAL;
	if ((area->flags & (VM_ALLOC | VM_ALLOW_HUGE_VMAP)) != VM_ALLOC)
		return -EINVAL;

	return 0;
}

bool arch_cpa_read_leaf(struct cpa_leaf *leaf)
{
	unsigned int cont;
	pteval_t val;

	switch (leaf->level) {
	case PGTABLE_LEVEL_PTE:
		val = pte_val(__ptep_get(leaf->entry));
		cont = CONT_PTES;
		break;
	case PGTABLE_LEVEL_PMD:
		val = pmd_val(pmdp_get(leaf->entry));
		cont = CONT_PMDS;
		break;
	case PGTABLE_LEVEL_PUD:
		/* with two levels the PMD level has the same entry */
		if (CONFIG_PGTABLE_LEVELS == 2)
			return false;
		val = pud_val(pudp_get(leaf->entry));
		cont = 1;
		break;
	default:
		return false;
	}

	if (leaf->level != PGTABLE_LEVEL_PTE) {
		if ((val & PMD_TYPE_MASK) == PMD_TYPE_TABLE)
			return false;
		val |= CPA_PAGE_BIT;
	}

	if (val & PTE_CONT)
		leaf->nr = cont;

	/* NS_SHARED is an address bit, but it is an attribute of the page */
	leaf->pfn = pte_pfn(__pte(val & ~PROT_NS_SHARED));
	val &= ~(__phys_to_pte_val(PFN_PHYS(leaf->pfn)) | PTE_CONT);

	if (val & PTE_VALID)
		val &= ~PTE_NG;
	if (!system_supports_bti_kernel() && !(val & PTE_PXN))
		val |= PTE_GP;

	leaf->prot = __pgprot(val);
	return true;
}

static void cpa_set_entry(enum pgtable_level level, void *entry, pteval_t val)
{
	switch (level) {
	case PGTABLE_LEVEL_PTE:
		__set_pte(entry, __pte(val));
		break;
	case PGTABLE_LEVEL_PMD:
		set_pmd(entry, __pmd(val));
		break;
	case PGTABLE_LEVEL_PUD:
		set_pud(entry, __pud(val));
		break;
	default:
		WARN_ON_ONCE(1);
	}
}

void arch_cpa_write_leaf(struct cpa_req *req, struct cpa_leaf *leaf,
			 pgprot_t prot)
{
	unsigned long step = (leaf->size / leaf->nr) >> PAGE_SHIFT;
	pteval_t val = pgprot_val(prot);
	/* entries of all levels are 64-bit */
	u64 *entry = leaf->entry;
	unsigned int i;

	if (val & PTE_VALID)
		val |= PTE_MAYBE_NG;
	if (!system_supports_bti_kernel())
		val &= ~PTE_GP;
	if (leaf->nr > 1)
		val |= PTE_CONT;
	if (leaf->level != PGTABLE_LEVEL_PTE)
		val &= ~CPA_PAGE_BIT;

	for (i = 0; i < leaf->nr; i++)
		cpa_set_entry(leaf->level, entry + i,
			      pte_val(pfn_pte(leaf->pfn + i * step,
					      __pgprot(val))));
}

/*
 * BBML3 allows the TLB to hold the leaves that were split, the changed ranges
 * cover them.
 */
void arch_cpa_flush(struct cpa_req *req)
{
	const struct cpa_prot_op *p = &arch_cpa_prot_ops[CPA_PROT_P];

	if (req->flags & CPA_NOFLUSH)
		return;

	/* invalid entries are not cached in the TLB */
	if (pgprot_val(req->set) == pgprot_val(p->set) &&
	    pgprot_val(req->clr) == pgprot_val(p->clr))
		return;

	cpa_flush_ranges(req);
}

static int __set_memory_enc_dec(unsigned long addr,
				int numpages,
				bool encrypt)
{
	struct cpa_req req = {
		.addr = addr,
		.numpages = numpages,
		.flags = CPA_NO_ALIAS,
	};
	phys_addr_t start, end;
	int ret;

	if (!is_realm_world())
		return 0;

	if (!__is_lm_address(addr))
		return -EINVAL;

	start = __virt_to_phys(addr);
	end = start + numpages * PAGE_SIZE;

	/*
	 * Break the mapping before we make any changes to avoid stale TLB
	 * entries or Synchronous External Aborts caused by RIPAS_EMPTY
	 */
	cpa_req_add_op(&req, CPA_PROT_NP);
	if (encrypt)
		req.clr = __pgprot(pgprot_val(req.clr) | PROT_NS_SHARED);
	else
		req.set = __pgprot(pgprot_val(req.set) | PROT_NS_SHARED);

	ret = cpa_change(&req);
	if (ret)
		return ret;

	if (encrypt)
		ret = rsi_set_memory_range_protected(start, end);
	else
		ret = rsi_set_memory_range_shared(start, end);

	if (ret)
		return ret;

	return set_memory_p(addr, numpages);
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
