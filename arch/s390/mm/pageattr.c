// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright IBM Corp. 2011
 * Author(s): Jan Glauber <jang@linux.vnet.ibm.com>
 */
#include <linux/cpufeature.h>
#include <linux/hugetlb.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <asm/cacheflush.h>
#include <asm/facility.h>
#include <asm/pgalloc.h>
#include <asm/kfence.h>
#include <asm/page.h>
#include <asm/asm.h>
#include <linux/pageattr.h>
#include <asm/set_memory.h>

void __storage_key_init_range(unsigned long start, unsigned long end)
{
	unsigned long boundary, size;

	while (start < end) {
		if (cpu_has_edat1()) {
			/* set storage keys for a 1MB frame */
			size = 1UL << 20;
			boundary = (start + size) & ~(size - 1);
			if (boundary <= end) {
				do {
					start = sske_frame(start, PAGE_DEFAULT_KEY);
				} while (start < boundary);
				continue;
			}
		}
		page_set_storage_key(start, PAGE_DEFAULT_KEY, 1);
		start += PAGE_SIZE;
	}
}

#ifdef CONFIG_PROC_FS
atomic_long_t __bootdata_preserved(direct_pages_count[PG_DIRECT_MAP_MAX]);

void arch_report_meminfo(struct seq_file *m)
{
	seq_printf(m, "DirectMap4k:    %8lu kB\n",
		   atomic_long_read(&direct_pages_count[PG_DIRECT_MAP_4K]) << 2);
	seq_printf(m, "DirectMap1M:    %8lu kB\n",
		   atomic_long_read(&direct_pages_count[PG_DIRECT_MAP_1M]) << 10);
	seq_printf(m, "DirectMap2G:    %8lu kB\n",
		   atomic_long_read(&direct_pages_count[PG_DIRECT_MAP_2G]) << 21);
}
#endif /* CONFIG_PROC_FS */

static void pgt_set(unsigned long *old, unsigned long new, unsigned long addr,
		    unsigned long dtt)
{
	unsigned long *table, mask;

	mask = 0;
	if (cpu_has_edat2()) {
		switch (dtt) {
		case CRDTE_DTT_REGION3:
			mask = ~(PTRS_PER_PUD * sizeof(pud_t) - 1);
			break;
		case CRDTE_DTT_SEGMENT:
			mask = ~(PTRS_PER_PMD * sizeof(pmd_t) - 1);
			break;
		case CRDTE_DTT_PAGE:
			mask = ~(PTRS_PER_PTE * sizeof(pte_t) - 1);
			break;
		}
		table = (unsigned long *)((unsigned long)old & mask);
		crdte(*old, new, table, dtt, addr, get_lowcore()->kernel_asce.val);
	} else {
		cspg(old, *old, new);
	}
}

/* Software bit ignored by the hardware for the self test */
#define _PAGE_CPA_TEST		_PAGE_UNUSED
/* The F bit of large leaves is ignored when the AV bit is clear */
#define _RSTE_CPA_TEST		0x0800UL

/* PTE bits and their counterparts in segment and region third entries */
static const unsigned long cpa_rste_bits[][2] = {
	{ _PAGE_INVALID,	_SEGMENT_ENTRY_INVALID },
	{ _PAGE_PROTECT,	_SEGMENT_ENTRY_PROTECT },
	{ _PAGE_NOEXEC,		_SEGMENT_ENTRY_NOEXEC },
	{ _PAGE_PRESENT,	_SEGMENT_ENTRY_PRESENT },
	{ _PAGE_SOFT_DIRTY,	_SEGMENT_ENTRY_SOFT_DIRTY },
	{ _PAGE_YOUNG,		_SEGMENT_ENTRY_YOUNG },
	{ _PAGE_DIRTY,		_SEGMENT_ENTRY_DIRTY },
	{ _PAGE_READ,		_SEGMENT_ENTRY_READ },
	{ _PAGE_WRITE,		_SEGMENT_ENTRY_WRITE },
	{ _PAGE_CPA_TEST,	_RSTE_CPA_TEST },
};

static unsigned long cpa_rste_to_prot(unsigned long rste)
{
	unsigned long prot = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(cpa_rste_bits); i++)
		if (rste & cpa_rste_bits[i][1])
			prot |= cpa_rste_bits[i][0];
	return prot;
}

static unsigned long cpa_prot_to_rste(unsigned long prot, unsigned long *mask)
{
	unsigned long rste = 0;
	int i;

	*mask = 0;
	for (i = 0; i < ARRAY_SIZE(cpa_rste_bits); i++) {
		*mask |= cpa_rste_bits[i][1];
		if (prot & cpa_rste_bits[i][0])
			rste |= cpa_rste_bits[i][1];
	}
	return rste;
}

static unsigned long cpa_origin_mask(enum pgtable_level level)
{
	switch (level) {
	case PGTABLE_LEVEL_PMD:
		return _SEGMENT_ENTRY_ORIGIN_LARGE;
	case PGTABLE_LEVEL_PUD:
		return _REGION3_ENTRY_ORIGIN_LARGE;
	default:
		return PAGE_MASK;
	}
}

static unsigned long cpa_mkleaf(enum pgtable_level level, unsigned long pfn,
				pgprot_t prot)
{
	unsigned long val = PFN_PHYS(pfn), mask;

	switch (level) {
	case PGTABLE_LEVEL_PMD:
		val |= _SEGMENT_ENTRY_LARGE;
		break;
	case PGTABLE_LEVEL_PUD:
		val |= _REGION_ENTRY_TYPE_R3 | _REGION3_ENTRY_LARGE;
		break;
	default:
		return val | pgprot_val(prot);
	}
	return val | cpa_prot_to_rste(pgprot_val(prot), &mask);
}

static unsigned long cpa_dtt(enum pgtable_level level)
{
	switch (level) {
	case PGTABLE_LEVEL_PMD:
		return CRDTE_DTT_SEGMENT;
	case PGTABLE_LEVEL_PUD:
		return CRDTE_DTT_REGION3;
	default:
		return CRDTE_DTT_PAGE;
	}
}

static bool cpa_entry_invalid(enum pgtable_level level, unsigned long val)
{
	if (level == PGTABLE_LEVEL_PTE)
		return val & _PAGE_INVALID;
	return val & _SEGMENT_ENTRY_INVALID;
}

/*
 * A valid entry may only be changed with an instruction that also purges
 * the TLB, but an invalid entry may be made valid with a single store.
 */
static void cpa_set_entry(enum pgtable_level level, unsigned long *entry,
			  unsigned long new, unsigned long addr)
{
	unsigned long old = READ_ONCE(*entry);

	if (old == new)
		return;
	if (cpa_entry_invalid(level, old))
		WRITE_ONCE(*entry, new);
	else
		pgt_set(entry, new, addr, cpa_dtt(level));
}

static bool cpa_in_identity_map(unsigned long addr)
{
	return addr - __identity_base < ident_map_size;
}

void arch_cpa_prot(enum cpa_prot_op op, pgprot_t *set, pgprot_t *clr)
{
	unsigned long s = 0, c = 0;

	switch (op) {
	case CPA_PROT_RO:
		s = _PAGE_PROTECT;
		c = _PAGE_WRITE;
		break;
	case CPA_PROT_RW:
		s = _PAGE_WRITE | _PAGE_DIRTY;
		c = _PAGE_PROTECT;
		break;
	case CPA_PROT_X:
		if (cpu_has_nx())
			c = _PAGE_NOEXEC;
		break;
	case CPA_PROT_NX:
		if (cpu_has_nx())
			s = _PAGE_NOEXEC;
		break;
	case CPA_PROT_NP:
	case CPA_PROT_INVALID:
		s = _PAGE_INVALID;
		break;
	case CPA_PROT_P:
		c = _PAGE_INVALID;
		break;
	case CPA_PROT_DEFAULT:
		s = pgprot_val(PAGE_KERNEL);
		c = _PAGE_INVALID | _PAGE_PROTECT;
		break;
	}

	*set = __pgprot(s);
	*clr = __pgprot(c);
}

void arch_cpa_read_leaf(struct cpa_leaf *leaf)
{
	unsigned long val = READ_ONCE(*(unsigned long *)leaf->entry);
	unsigned long origin = cpa_origin_mask(leaf->level);

	leaf->pfn = PHYS_PFN(val & origin);
	if (leaf->level == PGTABLE_LEVEL_PTE)
		leaf->prot = __pgprot(val & ~origin);
	else
		leaf->prot = __pgprot(cpa_rste_to_prot(val));
}

void arch_cpa_write_leaf(struct cpa_req *req, struct cpa_leaf *leaf,
			 pgprot_t prot)
{
	unsigned long *entry = leaf->entry;
	unsigned long old = READ_ONCE(*entry), new, mask;

	if (leaf->level == PGTABLE_LEVEL_PTE) {
		new = (old & PAGE_MASK) | pgprot_val(prot);
	} else {
		new = cpa_prot_to_rste(pgprot_val(prot), &mask);
		new |= old & ~mask;
	}
	cpa_set_entry(leaf->level, entry, new, leaf->start);
}

void *arch_cpa_alloc_table(struct cpa_req *req, enum pgtable_level level,
			   unsigned long addr)
{
	if (req->flags & CPA_ATOMIC)
		return NULL;

	/* the kernel mapping is changed before the page allocator is ready */
	if (!slab_is_available()) {
		if (level == PGTABLE_LEVEL_PTE)
			return vmem_pte_alloc();
		return vmem_crst_alloc(_SEGMENT_ENTRY_EMPTY);
	}

	if (level == PGTABLE_LEVEL_PTE)
		return pte_alloc_one_kernel(&init_mm);
	return pmd_alloc_one(&init_mm, addr);
}

static void cpa_update_page_count(struct cpa_leaf *leaf, bool split)
{
	long nr = split ? 1 : -1;

	if (!cpa_in_identity_map(leaf->start))
		return;

	if (leaf->level == PGTABLE_LEVEL_PMD) {
		update_page_count(PG_DIRECT_MAP_4K, nr * PTRS_PER_PTE);
		update_page_count(PG_DIRECT_MAP_1M, -nr);
	} else {
		update_page_count(PG_DIRECT_MAP_1M, nr * PTRS_PER_PMD);
		update_page_count(PG_DIRECT_MAP_2G, -nr);
	}
}

/* CRDTE and CSPG switch to the new table without an invalid window */
int arch_cpa_split(struct cpa_req *req, struct cpa_leaf *leaf, void *table)
{
	enum pgtable_level level = leaf->level - 1;
	unsigned long *entries = table, pointer;
	unsigned long step = PHYS_PFN(leaf->size) / PTRS_PER_PTE;
	int i, nr = PTRS_PER_PTE;

	if (leaf->level == PGTABLE_LEVEL_PUD) {
		step = PHYS_PFN(leaf->size) / PTRS_PER_PMD;
		nr = PTRS_PER_PMD;
		pointer = __pa(table) | _REGION3_ENTRY;
	} else {
		pointer = __pa(table) | _SEGMENT_ENTRY;
	}

	for (i = 0; i < nr; i++)
		entries[i] = cpa_mkleaf(level, leaf->pfn + i * step, leaf->prot);

	cpa_set_entry(leaf->level, leaf->entry, pointer, leaf->start);
	cpa_update_page_count(leaf, true);

	return 0;
}

int split_pud_page(pud_t *pudp, unsigned long addr)
{
	struct cpa_req req = { .addr = addr };
	struct cpa_leaf leaf = {
		.level = PGTABLE_LEVEL_PUD,
		.entry = pudp,
		.start = addr,
		.size = PUD_SIZE,
		.nr = 1,
	};
	void *table;
	int err;

	table = arch_cpa_alloc_table(&req, PGTABLE_LEVEL_PMD, addr);
	if (!table)
		return -ENOMEM;

	cpa_lock();
	arch_cpa_read_leaf(&leaf);
	err = arch_cpa_split(&req, &leaf, table);
	cpa_unlock();

	return err;
}

bool arch_cpa_can_collapse(struct cpa_req *req, enum pgtable_level level)
{
	if (level == PGTABLE_LEVEL_PMD)
		return cpu_has_edat1();
	return cpu_has_edat2();
}

bool arch_cpa_collapse(struct cpa_req *req, struct cpa_leaf *leaf)
{
	unsigned long new = cpa_mkleaf(leaf->level, leaf->pfn, leaf->prot);

	/*
	 * PTEs map real addresses and large leaves map absolute addresses,
	 * they differ for the first pages because of prefixing.
	 */
	if (!leaf->pfn)
		return false;

	cpa_set_entry(leaf->level, leaf->entry, new, leaf->start);
	cpa_update_page_count(leaf, false);

	return true;
}

bool arch_cpa_get_alias(struct cpa_req *req, struct cpa_range *range,
			unsigned long addr, unsigned long pfn,
			unsigned long nr, unsigned int idx,
			struct cpa_range *alias)
{
	unsigned long mask = _PAGE_PROTECT | _PAGE_WRITE | _PAGE_DIRTY;

	/*
	 * Only read-only permissions are applied to the direct map to keep
	 * it non-executable.
	 */
	if (idx || !cpa_linear_alias(addr, pfn, nr, alias))
		return false;

	alias->set = __pgprot(pgprot_val(range->set) & mask);
	alias->clr = __pgprot(pgprot_val(range->clr) & mask);

	return pgprot_val(alias->set) || pgprot_val(alias->clr);
}

pgprot_t arch_cpa_test_prot(void)
{
	return __pgprot(_PAGE_CPA_TEST);
}

static void cpa_req_add(struct cpa_req *req, enum cpa_prot_op op)
{
	pgprot_t set, clr;

	arch_cpa_prot(op, &set, &clr);
	req->set = __pgprot(pgprot_val(req->set) | pgprot_val(set));
	req->clr = __pgprot(pgprot_val(req->clr) | pgprot_val(clr));
}

int __set_memory(unsigned long addr, unsigned long numpages,
		 unsigned long flags)
{
	struct cpa_req req = {
		.addr = addr & PAGE_MASK,
		.numpages = numpages,
	};

	if (flags & SET_MEMORY_RO)
		cpa_req_add(&req, CPA_PROT_RO);
	if (flags & SET_MEMORY_X)
		cpa_req_add(&req, CPA_PROT_X);
	if (flags & SET_MEMORY_4K)
		req.flags |= CPA_SPLIT;

	return cpa_change(&req);
}

#if defined(CONFIG_DEBUG_PAGEALLOC) || defined(CONFIG_KFENCE)

static void ipte_range(pte_t *pte, unsigned long address, int nr)
{
	int i;

	if (test_facility(13)) {
		__ptep_ipte_range(address, nr - 1, pte, IPTE_GLOBAL);
		return;
	}
	for (i = 0; i < nr; i++) {
		__ptep_ipte(address, pte, 0, 0, IPTE_GLOBAL);
		address += PAGE_SIZE;
		pte++;
	}
}

void __kernel_map_pages(struct page *page, int numpages, int enable)
{
	unsigned long address;
	pte_t *ptep, pte;
	int nr, i, j;

	for (i = 0; i < numpages;) {
		address = (unsigned long)page_to_virt(page + i);
		ptep = virt_to_kpte(address);
		nr = (unsigned long)ptep >> ilog2(sizeof(long));
		nr = PTRS_PER_PTE - (nr & (PTRS_PER_PTE - 1));
		nr = min(numpages - i, nr);
		if (enable) {
			for (j = 0; j < nr; j++) {
				pte = ptep_get(ptep);
				pte = clear_pte_bit(pte, __pgprot(_PAGE_INVALID));
				set_pte(ptep, pte);
				address += PAGE_SIZE;
				ptep++;
			}
		} else {
			ipte_range(ptep, address, nr);
		}
		i += nr;
	}
}

#endif /* CONFIG_DEBUG_PAGEALLOC */
