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
static inline int set_direct_map_invalid_noflush(struct page *page,
						 unsigned int nr)
{
	return 0;
}
static inline int set_direct_map_default_noflush(struct page *page,
						 unsigned int nr)
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
#include <linux/spinlock.h>

/* Caller-requested behavior, stored in cpa_data.flags. */
#define CPA_ARRAY		BIT(0)
#define CPA_PAGES_ARRAY		BIT(1)
#define CPA_NO_CHECK_ALIAS	BIT(2)
#define CPA_COLLAPSE		BIT(3)
#define CPA_DEBUG_PAGEALLOC	BIT(4)
#define CPA_FORCE_SPLIT		BIT(5)

/* Internally maintained state, stored in cpa_data.state. */
#define CPA_FLUSHTLB		BIT(0)
#define CPA_FORCE_STATIC_PROT	BIT(1)
#define CPA_FORCE_FLUSH_ALL	BIT(2)
#define CPA_INIT_MM_READ_LOCKED	BIT(3)
#define CPA_ALIAS		BIT(4)

extern spinlock_t cpa_lock;

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
	unsigned int	state;
	struct page	**pages;
};

/*
 * context for checking for a split a large page and splitting it if required.
 */
struct cpa_split_data {
	unsigned long	address;
	unsigned long	psize;
	unsigned long	pmask;
	pte_t		*kpte;
	pte_t		*pbase;
	enum pgtable_level level;
	bool		nx;
	bool		rw;
};

unsigned long cpa_addr(struct cpa_data *cpa, unsigned long idx);
int cpa_revalidate_mapping(struct cpa_data *cpa, struct cpa_split_data *sd);
int cpa_prepare_split(struct cpa_data *cpa, struct cpa_split_data *sd);

int arch_cpa_process_fault(struct cpa_data *cpa, unsigned long vaddr);
int arch_cpa_process_alias(struct cpa_data *cpa);
int arch_should_split_large_page(struct cpa_data *cpa,
				 struct cpa_split_data *sd);
/* A zero return consumes sd->pbase; nonzero leaves it for the caller to free. */
int arch_split_large_page(struct cpa_data *cpa, struct cpa_split_data *sd);
void arch_change_pte(struct cpa_data *cpa, unsigned long address,
		     pte_t *kpte, pte_t old_pte, bool nx, bool rw);
void arch_cpa_flush(struct cpa_data *cpa, int err);

int __change_page_attr_set_clr(struct cpa_data *cpa);
int change_page_attr_set_clr(unsigned long *addr, int numpages,
			     pgprot_t mask_set, pgprot_t mask_clr,
			     unsigned int flags,
			     struct page **pages);

static inline int change_page_attr_set(unsigned long *addr, int numpages,
				       pgprot_t mask, int array)
{
	return change_page_attr_set_clr(addr, numpages, mask, __pgprot(0),
		(array ? CPA_ARRAY : 0), NULL);
}

static inline int change_page_attr_clear(unsigned long *addr, int numpages,
					 pgprot_t mask, int array)
{
	return change_page_attr_set_clr(addr, numpages, __pgprot(0), mask,
		(array ? CPA_ARRAY : 0), NULL);
}

static inline int cpa_set_pages_array(struct page **pages, int numpages,
				      pgprot_t mask)
{
	return change_page_attr_set_clr(NULL, numpages, mask, __pgprot(0),
		CPA_PAGES_ARRAY, pages);
}

static inline int cpa_clear_pages_array(struct page **pages, int numpages,
					pgprot_t mask)
{
	return change_page_attr_set_clr(NULL, numpages, __pgprot(0), mask,
		CPA_PAGES_ARRAY, pages);
}

#endif /* CONFIG_GENERIC_SET_MEMORY */

#endif /* _LINUX_SET_MEMORY_H_ */
