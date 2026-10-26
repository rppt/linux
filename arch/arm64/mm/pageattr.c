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

#include <asm/kfence.h>
#include <asm/pgalloc.h>
#include <asm/pgtable-prot.h>
#include <asm/tlbflush.h>

/* set in pages and clear in blocks, regardless of PTE_VALID */
#define CPA_PAGE_BIT	(PTE_TYPE_PAGE & ~PTE_VALID)

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

void arch_cpa_prot(enum cpa_prot_op op, pgprot_t *set, pgprot_t *clr)
{
	pteval_t s = 0, c = 0;

	/*
	 * PTE_PRESENT_INVALID aliases PTE_NG, the core clears the bits
	 * before setting them.
	 */
	switch (op) {
	case CPA_PROT_RO:
		s = PTE_RDONLY;
		c = PTE_WRITE;
		break;
	case CPA_PROT_RW:
		s = PTE_WRITE;
		c = PTE_RDONLY;
		break;
	case CPA_PROT_X:
		s = PTE_MAYBE_GP;
		c = PTE_PXN;
		break;
	case CPA_PROT_NX:
		s = PTE_PXN;
		c = PTE_MAYBE_GP;
		break;
	case CPA_PROT_NP:
	case CPA_PROT_INVALID:
		s = PTE_PRESENT_INVALID;
		c = PTE_PRESENT_VALID_KERNEL;
		break;
	case CPA_PROT_P:
		s = PTE_PRESENT_VALID_KERNEL;
		c = PTE_PRESENT_INVALID;
		break;
	case CPA_PROT_DEFAULT:
		s = PTE_PRESENT_VALID_KERNEL | PTE_WRITE;
		c = PTE_PRESENT_INVALID | PTE_RDONLY;
		break;
	}

	*set = __pgprot(s);
	*clr = __pgprot(c);
}

int arch_cpa_check_range(struct cpa_req *req)
{
	unsigned long start = (unsigned long)kasan_reset_tag((void *)req->addr);
	unsigned long end = start + req->numpages * PAGE_SIZE;
	struct vm_struct *area;

	if (__is_lm_address(start) && __is_lm_address(end - 1)) {
		/* PXNTable makes the linear map non-executable */
		if (pgprot_val(req->clr) & PTE_PXN)
			return -EINVAL;
		return 0;
	}

	/*
	 * The range must be covered by precisely one VM area that has the
	 * VM_ALLOC flag set, the kernel image and other mappings that have
	 * VM areas cannot be changed.
	 */
	area = find_vm_area((void *)start);
	if (!area || !(area->flags & VM_ALLOC) ||
	    end > (unsigned long)kasan_reset_tag(area->addr) + area->size)
		return -EINVAL;

	/*
	 * Get rid of potentially aliasing lazily unmapped vm areas that may
	 * have permissions set that deviate from the ones we are setting here.
	 */
	vm_unmap_aliases();

	return 0;
}

static unsigned long cpa_level_pages(enum pgtable_level level)
{
	switch (level) {
	case PGTABLE_LEVEL_PTE:
		return 1;
	case PGTABLE_LEVEL_PMD:
		return PMD_SIZE >> PAGE_SHIFT;
	default:
		return PUD_SIZE >> PAGE_SHIFT;
	}
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
	default:
		set_pud(entry, __pud(val));
		break;
	}
}

static pteval_t cpa_mkval(enum pgtable_level level, unsigned long pfn,
			  pgprot_t prot)
{
	pteval_t val = __phys_to_pte_val(PFN_PHYS(pfn)) | pgprot_val(prot);

	if (level == PGTABLE_LEVEL_PTE)
		val |= CPA_PAGE_BIT;

	return val;
}

/* Descriptors have the same size at all levels */
static void cpa_set_entries(enum pgtable_level level, void *entry,
			    unsigned int nr, unsigned long pfn, pgprot_t prot,
			    pteval_t cont)
{
	unsigned long step = cpa_level_pages(level);
	unsigned int i;

	for (i = 0; i < nr; i++)
		cpa_set_entry(level, (pteval_t *)entry + i,
			      cpa_mkval(level, pfn + i * step, prot) | cont);
}

/*
 * Leaves have the same format at all levels except for bit 1. The NS shared
 * bit of Realms is a part of the output address, but it is an attribute of
 * the mapping rather than a part of the pfn.
 */
void arch_cpa_read_leaf(struct cpa_leaf *leaf)
{
	pteval_t val = READ_ONCE(*(pteval_t *)leaf->entry);
	phys_addr_t phys = __pte_to_phys(__pte(val & ~PROT_NS_SHARED));

	leaf->pfn = __phys_to_pfn(phys);
	leaf->prot = __pgprot(val & ~(__phys_to_pte_val(phys) | CPA_PAGE_BIT |
				      PTE_CONT));

	if (val & PTE_CONT)
		leaf->nr = leaf->level == PGTABLE_LEVEL_PTE ? CONT_PTES :
							      CONT_PMDS;
}

/*
 * Only the permissions and the valid bit change, which does not require
 * break-before-make. All entries of a contiguous group are changed.
 */
void arch_cpa_write_leaf(struct cpa_req *req, struct cpa_leaf *leaf,
			 pgprot_t prot)
{
	cpa_set_entries(leaf->level, leaf->entry, leaf->nr, leaf->pfn, prot,
			leaf->nr > 1 ? PTE_CONT : 0);
}

/*
 * Changing the size of a valid mapping without break-before-make may cause
 * TLB conflict aborts unless the CPU supports BBML3.
 */
static bool cpa_can_resize(struct cpa_req *req, struct cpa_leaf *leaf)
{
	/* invalid entries are not cached in the TLB */
	if (!(pgprot_val(leaf->prot) & PTE_VALID))
		return true;

	/* CPA_ATOMIC requests run while other CPUs are off the page tables */
	if (req->flags & CPA_ATOMIC)
		return cpu_supports_bbml3();

	if (system_capabilities_finalized())
		return system_supports_bbml3();

	/* the boot CPU is the only user of the page tables */
	return num_online_cpus() == 1 && cpu_supports_bbml3();
}

void *arch_cpa_alloc_table(struct cpa_req *req, enum pgtable_level level,
			   unsigned long addr)
{
	gfp_t gfp = req->flags & CPA_ATOMIC ? GFP_ATOMIC : GFP_PGTABLE_KERNEL;
	phys_addr_t phys;

	if (WARN_ON_ONCE(!page_alloc_available))
		return NULL;

	phys = pgd_pgtable_alloc_init_mm_gfp(level, gfp);
	if (phys == INVALID_PHYS_ADDR)
		return NULL;

	return phys_to_virt(phys);
}

/*
 * The new entries map the same pfns with the same attributes as the leaf,
 * so with BBML3 stale TLB entries for the leaf are harmless.
 */
int arch_cpa_split(struct cpa_req *req, struct cpa_leaf *leaf, void *table)
{
	enum pgtable_level level = leaf->level - 1;
	unsigned int nr = leaf->size / (cpa_level_pages(level) << PAGE_SHIFT);
	pteval_t table_bits = PMD_TYPE_TABLE | PMD_TABLE_UXN | PMD_TABLE_AF;
	pteval_t cont = PTE_CONT;

	if (!cpa_can_resize(req, leaf))
		return -EOPNOTSUPP;

	/* CPA_SPLIT would split the contiguous groups right away */
	if (req->flags & CPA_SPLIT)
		cont = 0;

	cpa_set_entries(level, table, nr, leaf->pfn, leaf->prot, cont);

	/* the walker must not see a partially filled table */
	dsb(ishst);

	cpa_set_entry(leaf->level, leaf->entry,
		      __phys_to_pte_val(__pa(table)) | table_bits);

	return 0;
}

int arch_cpa_split_group(struct cpa_req *req, struct cpa_leaf *leaf)
{
	if (!cpa_can_resize(req, leaf))
		return -EOPNOTSUPP;

	cpa_set_entries(leaf->level, leaf->entry, leaf->nr, leaf->pfn,
			leaf->prot, 0);

	return 0;
}

bool arch_cpa_can_collapse(struct cpa_req *req, enum pgtable_level level)
{
	if (level == PGTABLE_LEVEL_PUD && !pud_sect_supported())
		return false;

	return system_supports_bbml3();
}

/*
 * Memory that can be hot-removed must not be mapped by a leaf that maps
 * other memory. Memory present at boot cannot be removed.
 */
static bool cpa_maps_removable_memory(struct cpa_leaf *leaf)
{
#ifdef CONFIG_MEMORY_HOTREMOVE
	unsigned long end = leaf->pfn + (leaf->size >> PAGE_SHIFT);
	unsigned long pfn;

	if (!__is_lm_address(leaf->start))
		return false;

	for (pfn = leaf->pfn; pfn < end; pfn += PAGES_PER_SECTION)
		if (!early_section(__pfn_to_section(pfn)))
			return true;
#endif
	return false;
}

bool arch_cpa_collapse(struct cpa_req *req, struct cpa_leaf *leaf)
{
	if (cpa_maps_removable_memory(leaf))
		return false;

	cpa_set_entry(leaf->level, leaf->entry,
		      cpa_mkval(leaf->level, leaf->pfn, leaf->prot));

	/* the table is freed after return, drop it from the walk caches */
	__flush_tlb_kernel_pgtable(leaf->start);

	return true;
}

/*
 * With rodata_full the linear alias of vmalloc memory follows its write
 * permissions.
 */
bool arch_cpa_get_alias(struct cpa_req *req, struct cpa_range *range,
			unsigned long addr, unsigned long pfn,
			unsigned long nr, unsigned int idx,
			struct cpa_range *alias)
{
	pteval_t mask = PTE_RDONLY | PTE_WRITE;
	pteval_t set = pgprot_val(range->set) & mask;
	pteval_t clr = pgprot_val(range->clr) & mask;

	if (idx || !rodata_full || !(set | clr))
		return false;

	if (!cpa_linear_alias(addr, pfn, nr, alias))
		return false;

	alias->set = __pgprot(set);
	alias->clr = __pgprot(clr);

	return true;
}

void arch_cpa_flush(struct cpa_req *req)
{
	/* invalid entries are not cached in the TLB */
	if (pgprot_val(req->set) == PTE_PRESENT_VALID_KERNEL &&
	    pgprot_val(req->clr) == PTE_PRESENT_INVALID)
		return;

	if (req->flush_start < req->flush_end)
		flush_tlb_kernel_range(req->flush_start, req->flush_end);
	if (req->alias_flush_start < req->alias_flush_end)
		flush_tlb_kernel_range(req->alias_flush_start,
				       req->alias_flush_end);
}

static int cpa_set_clear(unsigned long addr, int numpages, pteval_t set,
			 pteval_t clr)
{
	struct cpa_req req = {
		.addr = addr,
		.numpages = numpages,
		.set = __pgprot(set),
		.clr = __pgprot(clr),
	};

	if (numpages <= 0)
		return 0;

	return cpa_change(&req);
}

int set_memory_valid(unsigned long addr, int numpages, int enable)
{
	if (enable)
		return set_memory_p(addr, numpages);
	return set_memory_np(addr, numpages);
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
	ret = cpa_set_clear(addr, numpages, set_prot | PTE_PRESENT_INVALID,
			    clear_prot | PTE_PRESENT_VALID_KERNEL);

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
