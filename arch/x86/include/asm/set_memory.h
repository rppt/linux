/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_SET_MEMORY_H
#define _ASM_X86_SET_MEMORY_H

#include <asm/page.h>
#include <asm/sections.h>
#include <asm-generic/set_memory.h>
#include <asm/pgtable.h>

#define set_memory_rox set_memory_rox
int set_memory_rox(unsigned long addr, int numpages);

/*
 * The effective NX and RW bits of an intermediate page table entry
 */
#define pgtable_entry_nx(val)	((val) & _PAGE_NX)
#define pgtable_entry_rw(val)	((val) & _PAGE_RW)

/* CPA leaf-protection helpers, see the generic versions in <linux/set_memory.h> */
static inline pgprot_t cpa_pgprot_large_to_4k(pgprot_t prot)
{
	/* Clear PSE (aka _PAGE_PAT) and move the PAT bit to its 4k position */
	return pgprot_large_2_4k(prot);
}
#define cpa_pgprot_large_to_4k cpa_pgprot_large_to_4k

static inline pgprot_t cpa_pgprot_4k_to_large(pgprot_t prot)
{
	/* Move the PAT bit to its large-page position */
	return pgprot_4k_2_large(prot);
}
#define cpa_pgprot_4k_to_large cpa_pgprot_4k_to_large

static inline pgprot_t cpa_pgprot_fixup(pgprot_t prot)
{
	/*
	 * _PAGE_GLOBAL means "global page" for present PTEs, but it is also
	 * used to indicate _PAGE_PROTNONE for non-present PTEs. Clear it on
	 * non-present entries so a present->non-present transition is not
	 * misinterpreted as _PAGE_PROTNONE.
	 */
	if (!(pgprot_val(prot) & _PAGE_PRESENT))
		pgprot_val(prot) &= ~_PAGE_GLOBAL;

	return prot;
}
#define cpa_pgprot_fixup cpa_pgprot_fixup

/* W^X verification helpers, see the generic versions in <linux/set_memory.h> */
static inline bool cpa_check_wx(void)
{
	/*
	 * 32-bit has some unfixable W+X issues, like EFI code and writable
	 * data being in the same page, so only enforce on 64-bit. Also only
	 * verify when the CPU actually supports NX.
	 */
	return !IS_ENABLED(CONFIG_X86_32) && (__supported_pte_mask & _PAGE_NX);
}
#define cpa_check_wx cpa_check_wx

static inline bool cpa_pgprot_write(pgprot_t prot)
{
	return pgprot_val(prot) & _PAGE_RW;
}
#define cpa_pgprot_write cpa_pgprot_write

static inline bool cpa_pgprot_exec(pgprot_t prot)
{
	return !(pgprot_val(prot) & _PAGE_NX);
}
#define cpa_pgprot_exec cpa_pgprot_exec

static inline void cpa_set_pte(pte_t *ptep, pte_t pte)
{
	set_pte_atomic(ptep, pte);
}
#define cpa_set_pte cpa_set_pte

/*
 * Kernel text has an alias mapping at a high address ("highmap"); a direct-map
 * page that is part of the kernel image therefore has a highmap alias.
 */
static inline bool cpa_pfn_in_highmap(unsigned long pfn)
{
#ifdef CONFIG_X86_64
	unsigned long spfn = __pa_symbol(_text) >> PAGE_SHIFT;
	/* Do not reference a physical address outside the kernel. */
	unsigned long epfn = __pa_symbol(roundup(_brk_end, PMD_SIZE) - 1) >> PAGE_SHIFT;

	return pfn >= spfn && pfn <= epfn;
#else
	/* There is no highmap on 32-bit */
	return false;
#endif
}

static inline bool cpa_alias_needs_update(unsigned long vaddr, unsigned long pfn,
					  pgprot_t mask_set, pgprot_t mask_clr)
{
	/* Primary is not in the direct map: its direct-map alias needs update. */
	if (vaddr < PAGE_OFFSET ||
	    vaddr >= PAGE_OFFSET + (max_pfn_mapped << PAGE_SHIFT))
		return true;

	/* Direct-map page that is also part of the kernel image: highmap alias. */
	if ((vaddr < (unsigned long)_text || vaddr >= _brk_end) &&
	    cpa_pfn_in_highmap(pfn))
		return true;

	return false;
}
#define cpa_alias_needs_update cpa_alias_needs_update

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

int set_direct_map_invalid(const void *addr, unsigned long numpages);
int set_direct_map_default(const void *addr, unsigned long numpages);
bool kernel_page_present(struct page *page);

extern int kernel_set_to_readonly;

#endif /* _ASM_X86_SET_MEMORY_H */
