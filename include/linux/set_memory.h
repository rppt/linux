/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright 2017, Michael Ellerman, IBM Corporation.
 */
#ifndef _LINUX_SET_MEMORY_H_
#define _LINUX_SET_MEMORY_H_

#ifdef CONFIG_ARCH_HAS_SET_MEMORY
#include <asm/set_memory.h>
#else
static inline int __must_check set_memory_ro(unsigned long addr, int numpages) { return 0; }
static inline int __must_check set_memory_rw(unsigned long addr, int numpages) { return 0; }
static inline int __must_check set_memory_x(unsigned long addr,  int numpages) { return 0; }
static inline int __must_check set_memory_nx(unsigned long addr, int numpages) { return 0; }
#endif

#ifndef set_memory_rox
static inline int set_memory_rox(unsigned long addr, int numpages)
{
	int ret = set_memory_ro(addr, numpages);
	if (ret)
		return ret;
	return set_memory_x(addr, numpages);
}
#endif

#ifndef CONFIG_ARCH_HAS_SET_DIRECT_MAP
static inline int set_direct_map_invalid(const void *addr,
					 unsigned long numpages)
{
	return 0;
}
static inline int set_direct_map_default(const void *addr,
					 unsigned long numpages)
{
	return 0;
}

static inline bool kernel_page_present(struct page *page)
{
	return true;
}
#else /* CONFIG_ARCH_HAS_SET_DIRECT_MAP */
/*
 * Some architectures, e.g. ARM64 can disable direct map modifications at
 * boot time. Let them overrive this query.
 */
#ifndef can_set_direct_map
static inline bool can_set_direct_map(void)
{
	return true;
}
#define can_set_direct_map can_set_direct_map
#endif
#endif /* CONFIG_ARCH_HAS_SET_DIRECT_MAP */

#ifdef CONFIG_X86_64
int set_mce_nospec(unsigned long pfn);
int clear_mce_nospec(unsigned long pfn);
#else
static inline int set_mce_nospec(unsigned long pfn)
{
	return 0;
}
static inline int clear_mce_nospec(unsigned long pfn)
{
	return 0;
}
#endif

#ifndef CONFIG_ARCH_HAS_MEM_ENCRYPT
static inline int set_memory_encrypted(unsigned long addr, int numpages)
{
	return 0;
}

static inline int set_memory_decrypted(unsigned long addr, int numpages)
{
	return 0;
}
#endif /* CONFIG_ARCH_HAS_MEM_ENCRYPT */

#ifdef CONFIG_GENERIC_SET_MEMORY

#include <linux/pgtable.h>

/*
 * The effective NX and RW bits of an intermediate (non-leaf) page table
 * entry value. Must be overridden by architectures where the intermediate
 * page table levels restrict the effective permissions of the leaf
 * entries.
 */
#ifndef pgtable_entry_nx
#define pgtable_entry_nx(val)	false
#define pgtable_entry_rw(val)	true
#endif

/*
 * Helpers used to compute the page-protection bits of a leaf entry in the
 * generic CPA loop. Architectures with a special leaf-protection encoding
 * override these in <asm/set_memory.h>; the generic versions are identity.
 */

/*
 * Convert a leaf protection value between the large (huge) page encoding and
 * the PTE encoding. On some architectures (e.g. x86) the caching-mode (PAT)
 * bit lives at a different position in the two formats.
 */
#ifndef cpa_pgprot_large_to_4k
static inline pgprot_t cpa_pgprot_large_to_4k(pgprot_t prot)
{
	return prot;
}
#define cpa_pgprot_large_to_4k cpa_pgprot_large_to_4k
#endif

#ifndef cpa_pgprot_4k_to_large
static inline pgprot_t cpa_pgprot_4k_to_large(pgprot_t prot)
{
	return prot;
}
#define cpa_pgprot_4k_to_large cpa_pgprot_4k_to_large
#endif

/*
 * Architecture fixup applied to a freshly computed leaf protection before it
 * is installed (e.g. x86 clears the global bit on non-present entries so it
 * is not misinterpreted as _PAGE_PROTNONE).
 */
#ifndef cpa_pgprot_fixup
static inline pgprot_t cpa_pgprot_fixup(pgprot_t prot)
{
	return prot;
}
#define cpa_pgprot_fixup cpa_pgprot_fixup
#endif

/*
 * Apply the CPA clear/set masks to a protection value. Clearing is always
 * done before setting because some architectures use clear/set bits that
 * alias each other.
 */
static inline pgprot_t cpa_pgprot_apply_masks(pgprot_t prot, pgprot_t clr,
					      pgprot_t set)
{
	return __pgprot((pgprot_val(prot) & ~pgprot_val(clr)) |
			pgprot_val(set));
}

/*
 * Strict W^X (write xor execute) verification for the generic CPA loop.
 *
 * An architecture opts into the check by overriding cpa_check_wx() (which may
 * also gate it on runtime NX support) and by reporting whether a leaf
 * protection value is writable / executable through cpa_pgprot_write() and
 * cpa_pgprot_exec(). The write and execute permission bits are position
 * invariant across page table levels on the architectures that implement
 * this, so a single pgprot based test serves all levels. The generic defaults
 * disable the check.
 */
#ifndef cpa_check_wx
static inline bool cpa_check_wx(void)
{
	return false;
}
#define cpa_check_wx cpa_check_wx
#endif

#ifndef cpa_pgprot_write
static inline bool cpa_pgprot_write(pgprot_t prot)
{
	return false;
}
#define cpa_pgprot_write cpa_pgprot_write
#endif

#ifndef cpa_pgprot_exec
static inline bool cpa_pgprot_exec(pgprot_t prot)
{
	return false;
}
#define cpa_pgprot_exec cpa_pgprot_exec
#endif

/*
 * Validate strict W^X semantics. Warn when a leaf is about to become both
 * writable and executable, unless a non-leaf entry along the walk already
 * disables writing (!rw) or execution (nx).
 */
static inline pgprot_t verify_rwx(pgprot_t old, pgprot_t new, unsigned long start,
				  unsigned long pfn, unsigned long npg,
				  bool nx, bool rw)
{
	unsigned long end;

	if (!cpa_check_wx())
		return new;

	/* Nothing to check if neither writability nor executability changes */
	if (cpa_pgprot_write(old) == cpa_pgprot_write(new) &&
	    cpa_pgprot_exec(old) == cpa_pgprot_exec(new))
		return new;

	/* Only a leaf that becomes writable and executable is a concern */
	if (!(cpa_pgprot_write(new) && cpa_pgprot_exec(new)))
		return new;

	/* Non-leaf translation entries can disable writing or execution. */
	if (!rw || nx)
		return new;

	end = start + npg * PAGE_SIZE - 1;
	WARN_ONCE(1, "CPA detected W^X violation: %016llx -> %016llx range: 0x%016lx - 0x%016lx PFN %lx\n",
		  (unsigned long long)pgprot_val(old),
		  (unsigned long long)pgprot_val(new),
		  start, end, pfn);

	/*
	 * For now, allow all permission change attempts by returning the
	 * attempted permissions.  This can 'return old' to actively
	 * refuse the permission change at a later time.
	 */
	return new;
}

#define CPA_FLUSHTLB 1
#define CPA_ARRAY 2
#define CPA_PAGES_ARRAY 4
#define CPA_NO_CHECK_ALIAS 8 /* Do not search for aliases */
#define CPA_COLLAPSE 16 /* try to collapse large pages */

struct cpa_arch_info {
	spinlock_t *lock;
	/*
	 * The architecture serializes kernel page table updates by other
	 * means and may call set_memory APIs from atomic context, so the
	 * CPA loop must not take cpa_lock.
	 */
	bool no_cpa_lock;
};

struct cpa_arch_info *cpa_arch_setup(void);

void cpa_init(void);

/*
 * The current flushing context - we pass it instead of 5 arguments:
 */
struct cpa_data {
	unsigned long	*vaddr;
	pgd_t		*pgd;
	pgprot_t	mask_set;
	pgprot_t	mask_clr;
	unsigned long	numpages;
	unsigned long	curpage;
	unsigned long	pfn;
	unsigned int	flags;
	unsigned int	force_split		: 1,
			force_static_prot	: 1,
			force_flush_all		: 1;
	struct page	**pages;
};

pte_t *lookup_address_in_pgd_attr(pgd_t *pgd, unsigned long address,
				  unsigned int *level, bool *nx, bool *rw);
pte_t *lookup_address_in_pgd(pgd_t *pgd, unsigned long address,
			     unsigned int *level);
pte_t *lookup_address(unsigned long address, unsigned int *level);

unsigned long cpa_addr(struct cpa_data *cpa, unsigned long idx);

void arch_cpa_flush(struct cpa_data *cpa, int err);
int arch_cpa_process_fault(struct cpa_data *cpa, unsigned long vaddr,
			   int primary);
int arch_cpa_process_alias(struct cpa_data *cpa);
int arch_should_split_large_page(pte_t *kpte, unsigned long address,
				 struct cpa_data *cpa, unsigned int level,
				 bool nx, bool rw);
int arch_split_large_page(struct cpa_data *cpa, pte_t *kpte,
			  unsigned long address, unsigned int level,
			  struct ptdesc *ptdesc);
void arch_change_pte(struct cpa_data *cpa, unsigned long address,
		     pte_t *kpte, pte_t old_pte, bool nx, bool rw);

int __change_page_attr_set_clr(struct cpa_data *cpa, int primary);
int change_page_attr_set_clr(unsigned long *addr, int numpages,
			     pgprot_t mask_set, pgprot_t mask_clr,
			     int force_split, int in_flag,
			     struct page **pages);

static inline int change_page_attr_set(unsigned long *addr, int numpages,
				       pgprot_t mask, int array)
{
	return change_page_attr_set_clr(addr, numpages, mask, __pgprot(0), 0,
		(array ? CPA_ARRAY : 0), NULL);
}

static inline int change_page_attr_clear(unsigned long *addr, int numpages,
					 pgprot_t mask, int array)
{
	return change_page_attr_set_clr(addr, numpages, __pgprot(0), mask, 0,
		(array ? CPA_ARRAY : 0), NULL);
}

static inline int cpa_set_pages_array(struct page **pages, int numpages,
				       pgprot_t mask)
{
	return change_page_attr_set_clr(NULL, numpages, mask, __pgprot(0), 0,
		CPA_PAGES_ARRAY, pages);
}

static inline int cpa_clear_pages_array(struct page **pages, int numpages,
					 pgprot_t mask)
{
	return change_page_attr_set_clr(NULL, numpages, __pgprot(0), mask, 0,
		CPA_PAGES_ARRAY, pages);
}

#else /* CONFIG_GENERIC_SET_MEMORY */

static inline void cpa_init(void)
{
}

#endif /* CONFIG_GENERIC_SET_MEMORY */

#endif /* _LINUX_SET_MEMORY_H_ */
