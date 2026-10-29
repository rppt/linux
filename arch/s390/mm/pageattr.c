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
#include <linux/pageattr.h>
#include <asm/cacheflush.h>
#include <asm/facility.h>
#include <asm/pgalloc.h>
#include <asm/kfence.h>
#include <asm/page.h>
#include <asm/asm.h>
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

/*
 * Segment and region third entries use the same protection bits, @rste is
 * the counterpart of the PTE bit @pte in both of them.
 */
static const struct {
	unsigned long pte;
	unsigned long rste;
} cpa_rste_bits[] = {
	{ _PAGE_INVALID,	_SEGMENT_ENTRY_INVALID },
	{ _PAGE_PROTECT,	_SEGMENT_ENTRY_PROTECT },
	{ _PAGE_NOEXEC,		_SEGMENT_ENTRY_NOEXEC },
	{ _PAGE_PRESENT,	_SEGMENT_ENTRY_PRESENT },
	{ _PAGE_SOFT_DIRTY,	_SEGMENT_ENTRY_SOFT_DIRTY },
	{ _PAGE_YOUNG,		_SEGMENT_ENTRY_YOUNG },
	{ _PAGE_DIRTY,		_SEGMENT_ENTRY_DIRTY },
	{ _PAGE_READ,		_SEGMENT_ENTRY_READ },
	{ _PAGE_WRITE,		_SEGMENT_ENTRY_WRITE },
};

static const struct cpa_level {
	unsigned long leaf_mask;	/* bits that identify a leaf */
	unsigned long leaf;
	unsigned long origin;		/* address bits of a leaf */
	unsigned long invalid;
	unsigned long table;		/* bits of a pointer to a table */
	unsigned long dtt;
	unsigned int ptrs;		/* entries in a table of this level */
	unsigned int pages;		/* pages mapped by a leaf */
	int count;
} cpa_levels[] = {
	[PGTABLE_LEVEL_PTE] = {
		.origin = PAGE_MASK,
		.invalid = _PAGE_INVALID,
		.dtt = CRDTE_DTT_PAGE,
		.ptrs = PTRS_PER_PTE,
		.pages = 1,
		.count = PG_DIRECT_MAP_4K,
	},
	[PGTABLE_LEVEL_PMD] = {
		.leaf_mask = _SEGMENT_ENTRY_LARGE,
		.leaf = _SEGMENT_ENTRY_LARGE,
		.origin = _SEGMENT_ENTRY_ORIGIN_LARGE,
		.invalid = _SEGMENT_ENTRY_INVALID,
		.table = _SEGMENT_ENTRY,
		.dtt = CRDTE_DTT_SEGMENT,
		.ptrs = PTRS_PER_PMD,
		.pages = PMD_SIZE >> PAGE_SHIFT,
		.count = PG_DIRECT_MAP_1M,
	},
	[PGTABLE_LEVEL_PUD] = {
		.leaf_mask = _REGION_ENTRY_TYPE_MASK | _REGION3_ENTRY_LARGE,
		.leaf = _REGION_ENTRY_TYPE_R3 | _REGION3_ENTRY_LARGE,
		.origin = _REGION3_ENTRY_ORIGIN_LARGE,
		.invalid = _REGION_ENTRY_INVALID,
		.table = _REGION3_ENTRY,
		.dtt = CRDTE_DTT_REGION3,
		.ptrs = PTRS_PER_PUD,
		.pages = PUD_SIZE >> PAGE_SHIFT,
		.count = PG_DIRECT_MAP_2G,
	},
};

struct cpa_prot_op arch_cpa_prot_ops[CPA_PROT_NR] __ro_after_init = {
	[CPA_PROT_RO] = {
		.set = __pgprot(_PAGE_PROTECT),
		.clr = __pgprot(_PAGE_WRITE),
		.alias = true,
	},
	[CPA_PROT_RW] = {
		.set = __pgprot(_PAGE_WRITE | _PAGE_DIRTY),
		.clr = __pgprot(_PAGE_PROTECT),
		.alias = true,
	},
	[CPA_PROT_X]  = { .clr = __pgprot(_PAGE_NOEXEC) },
	[CPA_PROT_NX] = { .set = __pgprot(_PAGE_NOEXEC) },
	[CPA_PROT_NP] = { .set = __pgprot(_PAGE_INVALID) },
	[CPA_PROT_P]  = { .clr = __pgprot(_PAGE_INVALID) },
	[CPA_PROT_INVALID] = { .set = __pgprot(_PAGE_INVALID) },
	[CPA_PROT_DEFAULT] = {
		.set = __pgprot(__PAGE_KERNEL),
		.clr = __pgprot(_PAGE_INVALID | _PAGE_PROTECT),
	},
};

/* _PAGE_NOEXEC requires the instruction-execution-protection facility */
void __init set_memory_init(void)
{
	int i;

	for (i = 0; i < CPA_PROT_NR; i++) {
		struct cpa_prot_op *p = &arch_cpa_prot_ops[i];

		p->set = __pgprot(pgprot_val(p->set) & page_noexec_mask);
		p->clr = __pgprot(pgprot_val(p->clr) & page_noexec_mask);
	}
}

static unsigned long cpa_rste_to_prot(unsigned long rste)
{
	unsigned long prot = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(cpa_rste_bits); i++) {
		if (rste & cpa_rste_bits[i].rste)
			prot |= cpa_rste_bits[i].pte;
	}

	return prot;
}

/* Replace the protection bits of @rste with @prot */
static unsigned long cpa_prot_to_rste(unsigned long rste, unsigned long prot)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(cpa_rste_bits); i++) {
		rste &= ~cpa_rste_bits[i].rste;
		if (prot & cpa_rste_bits[i].pte)
			rste |= cpa_rste_bits[i].rste;
	}

	return rste;
}

static unsigned long cpa_mkleaf(enum pgtable_level level, unsigned long pfn,
				unsigned long prot)
{
	unsigned long val = PFN_PHYS(pfn) | cpa_levels[level].leaf;

	if (level == PGTABLE_LEVEL_PTE)
		return val | prot;

	return cpa_prot_to_rste(val, prot);
}

/*
 * A valid entry may only be changed with an instruction that also purges
 * the TLB, but an invalid entry may be made valid with a plain store.
 */
static void cpa_set_entry(enum pgtable_level level, unsigned long *entry,
			  unsigned long new, unsigned long addr)
{
	const struct cpa_level *l = &cpa_levels[level];
	unsigned long old = READ_ONCE(*entry);

	if (old & l->invalid) {
		WRITE_ONCE(*entry, new);
		return;
	}

	pgt_set(entry, new, addr, l->dtt);
}

bool arch_cpa_read_leaf(struct cpa_leaf *leaf)
{
	const struct cpa_level *l;
	unsigned long val;

	if (leaf->level > PGTABLE_LEVEL_PUD)
		return false;

	l = &cpa_levels[leaf->level];
	val = READ_ONCE(*(unsigned long *)leaf->entry);
	if ((val & l->leaf_mask) != l->leaf)
		return false;

	leaf->pfn = PHYS_PFN(val & l->origin);
	if (leaf->level == PGTABLE_LEVEL_PTE)
		leaf->prot = __pgprot(val & ~l->origin);
	else
		leaf->prot = __pgprot(cpa_rste_to_prot(val));

	return true;
}

void arch_cpa_write_leaf(struct cpa_req *req, struct cpa_leaf *leaf,
			 pgprot_t prot)
{
	unsigned long *entry = leaf->entry;
	unsigned long new;

	if (leaf->level == PGTABLE_LEVEL_PTE)
		new = cpa_mkleaf(leaf->level, leaf->pfn, pgprot_val(prot));
	else
		new = cpa_prot_to_rste(READ_ONCE(*entry), pgprot_val(prot));

	cpa_set_entry(leaf->level, entry, new, leaf->start);
}

static void cpa_count_split(struct cpa_leaf *leaf)
{
	enum pgtable_level level = leaf->level - 1;

	if (leaf->start - __identity_base >= ident_map_size)
		return;

	update_page_count(cpa_levels[level].count, cpa_levels[level].ptrs);
	update_page_count(cpa_levels[leaf->level].count, -1);
}

/* CRDTE and CSPG replace a leaf with a table without an invalid window */
static int cpa_split_leaf(struct cpa_leaf *leaf)
{
	enum pgtable_level level = leaf->level - 1;
	const struct cpa_level *l = &cpa_levels[level];
	unsigned long *table, pfn = leaf->pfn;
	unsigned int i;

	if (level == PGTABLE_LEVEL_PTE)
		table = (unsigned long *)vmem_pte_alloc();
	else
		table = vmem_crst_alloc(_SEGMENT_ENTRY_EMPTY);
	if (!table)
		return -ENOMEM;

	for (i = 0; i < l->ptrs; i++, pfn += l->pages)
		table[i] = cpa_mkleaf(level, pfn, pgprot_val(leaf->prot));

	cpa_set_entry(leaf->level, leaf->entry,
		      __pa(table) | cpa_levels[leaf->level].table, leaf->start);
	cpa_count_split(leaf);

	return 0;
}

int arch_cpa_split(struct cpa_req *req, struct cpa_leaf *leaf)
{
	/* the page table allocators may sleep */
	if (req->flags & CPA_ATOMIC)
		return -ENOMEM;

	return cpa_split_leaf(leaf);
}

int split_pud_page(pud_t *pudp, unsigned long addr)
{
	struct cpa_leaf leaf = {
		.level = PGTABLE_LEVEL_PUD,
		.entry = pudp,
		.start = addr,
		.size = PUD_SIZE,
		.nr = 1,
	};

	if (!arch_cpa_read_leaf(&leaf))
		return 0;

	return cpa_split_leaf(&leaf);
}

/* Every change of a valid entry purges the TLB */
void arch_cpa_flush(struct cpa_req *req)
{
}

int __set_memory(unsigned long addr, unsigned long numpages,
		 unsigned long flags)
{
	struct cpa_req req = {
		.addr = addr & PAGE_MASK,
		.numpages = numpages,
	};

	if (flags & SET_MEMORY_RO)
		cpa_req_add_op(&req, CPA_PROT_RO);
	if (flags & SET_MEMORY_X)
		cpa_req_add_op(&req, CPA_PROT_X);
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
