/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_SET_MEMORY_H
#define _ASM_X86_SET_MEMORY_H

#include <linux/pgtable.h>

#include <asm/page.h>
#include <asm/sections.h>
#include <asm-generic/set_memory.h>

#define set_memory_rox set_memory_rox
int set_memory_rox(unsigned long addr, int numpages);

/*
 * The set_memory_* API can be used to change various attributes of a virtual
 * address range. The attributes include:
 * Cacheability  : UnCached, WriteCombining, WriteThrough, WriteBack
 * Executability : eXecutable, NoteXecutable
 * Read/Write    : ReadOnly, ReadWrite
 * Presence      : NotPresent
 * Encryption    : Encrypted, Decrypted
 *
 * Within a category, the attributes are mutually exclusive.
 *
 * The implementation of this API will take care of various aspects that
 * are associated with changing such attributes, such as:
 * - Flushing TLBs
 * - Flushing CPU caches
 * - Making sure aliases of the memory behind the mapping don't violate
 *   coherency rules as defined by the CPU in the system.
 *
 * What this API does not do:
 * - Provide exclusion between various callers - including callers that
 *   operation on other mappings of the same physical page
 * - Restore default attributes when a page is freed
 * - Guarantee that mappings other than the requested one are
 *   in any state, other than that these do not violate rules for
 *   the CPU you have. Do not depend on any effects on other mappings,
 *   CPUs other than the one you have may have more relaxed rules.
 * The caller is required to take care of these.
 */

int _set_memory_uc(unsigned long addr, int numpages);
int _set_memory_wc(unsigned long addr, int numpages);
int _set_memory_wt(unsigned long addr, int numpages);
int _set_memory_wb(unsigned long addr, int numpages);
int set_memory_uc(unsigned long addr, int numpages);
int set_memory_wc(unsigned long addr, int numpages);
int set_memory_wb(unsigned long addr, int numpages);
int set_memory_np(unsigned long addr, int numpages);
int set_memory_p(unsigned long addr, int numpages);
int set_memory_4k(unsigned long addr, int numpages);

bool set_memory_enc_stop_conversion(void);
int set_memory_encrypted(unsigned long addr, int numpages);
int set_memory_decrypted(unsigned long addr, int numpages);

int set_memory_np_noalias(unsigned long addr, int numpages);
int set_memory_nonglobal(unsigned long addr, int numpages);
int set_memory_global(unsigned long addr, int numpages);

int set_pages_array_uc(struct page **pages, int addrinarray);
int set_pages_array_wc(struct page **pages, int addrinarray);
int set_pages_array_wb(struct page **pages, int addrinarray);

/*
 * For legacy compatibility with the old APIs, a few functions
 * are provided that work on a "struct page".
 * These functions operate ONLY on the 1:1 kernel mapping of the
 * memory that the struct page represents, and internally just
 * call the set_memory_* function. See the description of the
 * set_memory_* function for more details on conventions.
 *
 * These APIs should be considered *deprecated* and are likely going to
 * be removed in the future.
 * The reason for this is the implicit operation on the 1:1 mapping only,
 * making this not a generally useful API.
 *
 * Specifically, many users of the old APIs had a virtual address,
 * called virt_to_page() or vmalloc_to_page() on that address to
 * get a struct page* that the old API required.
 * To convert these cases, use set_memory_*() on the original
 * virtual address, do not use these functions.
 */

int set_pages_uc(struct page *page, int numpages);
int set_pages_wb(struct page *page, int numpages);
int set_pages_ro(struct page *page, int numpages);
int set_pages_rw(struct page *page, int numpages);

int set_direct_map_invalid_noflush(struct page *page, unsigned int nr);
int set_direct_map_default_noflush(struct page *page, unsigned int nr);
bool kernel_page_present(struct page *page);

#ifdef CONFIG_PROC_FS
void update_page_count(enum pgtable_level level, unsigned long pages);
#else
static inline void update_page_count(enum pgtable_level level,
				     unsigned long pages) { }
#endif

/*
 * Helper function that returns the kernel pagetable entry controlling
 * the virtual address 'address'. NULL means no pagetable entry present.
 * NOTE: the return type is pte_t but if the pmd is PSE then we return it
 * as a pte too.
 */
pte_t *lookup_address(unsigned long address, enum pgtable_level *level);
pte_t *lookup_address_in_pgd(pgd_t *pgd, unsigned long address,
			     enum pgtable_level *level);
pte_t *lookup_address_in_pgd_attr(pgd_t *pgd, unsigned long address,
				  enum pgtable_level *level, bool *nx,
				  bool *rw);
pmd_t *lookup_pmd_address(unsigned long address);
phys_addr_t slow_virt_to_phys(void *__address);
int __init kernel_map_pages_in_pgd(pgd_t *pgd, u64 pfn,
				   unsigned long address,
				   unsigned numpages,
				   unsigned long page_flags);
int __init kernel_unmap_pages_in_pgd(pgd_t *pgd, unsigned long address,
				     unsigned long numpages);

extern int kernel_set_to_readonly;

#ifdef CONFIG_X86_64
/*
 * The kernel image is mapped into two places in the virtual address space
 * (addresses without KASLR, of course):
 *
 * 1. The kernel direct map (0xffff880000000000)
 * 2. The "high kernel map" (0xffffffff81000000)
 *
 * We actually execute out of #2. If we get the address of a kernel symbol, it
 * points to #2, but almost all physical-to-virtual translations point to #1.
 *
 * This is so that we can have both a directmap of all physical memory *and*
 * take full advantage of the limited (s32) immediate addressing range (2G)
 * of x86_64.
 *
 * See Documentation/arch/x86/x86_64/mm.rst for more detail.
 */
static inline unsigned long highmap_start_pfn(void)
{
	return __pa_symbol(_text) >> PAGE_SHIFT;
}

static inline unsigned long highmap_end_pfn(void)
{
	/* Do not reference physical address outside the kernel. */
	return __pa_symbol(roundup(_brk_end, PMD_SIZE) - 1) >> PAGE_SHIFT;
}

static inline bool cpa_pfn_in_highmap(unsigned long pfn)
{
	return pfn >= highmap_start_pfn() && pfn <= highmap_end_pfn();
}
#else
static inline bool cpa_pfn_in_highmap(unsigned long pfn)
{
	/* There is no highmap on 32-bit */
	return false;
}
#endif

/*
 * The direct map aliases all of physical memory, and on 64-bit the kernel
 * text is aliased by the high mapping.  A change to one of them has to be
 * applied to the others.
 *
 * Keep this inline: it runs once per page and says no most of the time.
 */
static inline bool arch_cpa_needs_alias(unsigned long vaddr, unsigned long pfn)
{
	unsigned long dmap_end = PAGE_OFFSET + (max_pfn_mapped << PAGE_SHIFT);

	if (!pfn_range_is_mapped(pfn, pfn + 1))
		return false;

	if (vaddr < PAGE_OFFSET || vaddr >= dmap_end)
		return true;

	return !(vaddr >= (unsigned long)_text && vaddr < _brk_end) &&
	       cpa_pfn_in_highmap(pfn);
}

#define arch_cpa_needs_alias arch_cpa_needs_alias

#endif /* _ASM_X86_SET_MEMORY_H */
