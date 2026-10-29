// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2019 SiFive
 */

#include <linux/mm.h>
#include <linux/pageattr.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

/* The direct map alias of the kernel image and vmalloc is never executable */
struct cpa_prot_op arch_cpa_prot_ops[CPA_PROT_NR] __ro_after_init = {
	[CPA_PROT_RO] = {
		.set = __pgprot(_PAGE_READ),
		.clr = __pgprot(_PAGE_WRITE),
		.alias = true,
	},
	[CPA_PROT_RW] = {
		/* W without R is reserved */
		.set = __pgprot(_PAGE_READ | _PAGE_WRITE),
		.alias = true,
	},
	[CPA_PROT_X]  = { .set = __pgprot(_PAGE_EXEC) },
	[CPA_PROT_NX] = { .clr = __pgprot(_PAGE_EXEC) },
	[CPA_PROT_NP] = { .clr = __pgprot(_PAGE_PRESENT) },
	[CPA_PROT_P]  = { .set = __pgprot(_PAGE_PRESENT) },
	[CPA_PROT_INVALID] = { .clr = __pgprot(_PAGE_PRESENT) },
	[CPA_PROT_DEFAULT] = {
		.set = PAGE_KERNEL,
		.clr = __pgprot(_PAGE_EXEC),
	},
};

static void cpa_set_entry(enum pgtable_level level, void *entry,
			  unsigned long val)
{
	switch (level) {
	case PGTABLE_LEVEL_PTE:
		set_pte(entry, __pte(val));
		break;
	case PGTABLE_LEVEL_PMD:
		set_pmd(entry, __pmd(val));
		break;
	case PGTABLE_LEVEL_PUD:
		set_pud(entry, __pud(val));
		break;
	case PGTABLE_LEVEL_P4D:
		set_p4d(entry, __p4d(val));
		break;
	default:
		WARN_ON_ONCE(1);
	}
}

static unsigned long cpa_mkval(unsigned long pfn, pgprot_t prot)
{
	return (pfn << _PAGE_PFN_SHIFT) | pgprot_val(prot);
}

/*
 * Leaves have the same format at all levels and have at least one of R, W
 * or X set, even when they are not present.
 */
bool arch_cpa_read_leaf(struct cpa_leaf *leaf)
{
	unsigned long val;

	switch (leaf->level) {
	case PGTABLE_LEVEL_PTE:
		val = pte_val(ptep_get(leaf->entry));
		break;
	case PGTABLE_LEVEL_PMD:
		val = pmd_val(pmdp_get(leaf->entry));
		break;
	case PGTABLE_LEVEL_PUD:
		/* folded on RV32 */
		if (!IS_ENABLED(CONFIG_64BIT))
			return false;
		val = pud_val(pudp_get(leaf->entry));
		break;
	case PGTABLE_LEVEL_P4D:
		/* folded without Sv57 */
		if (!pgtable_l5_enabled)
			return false;
		val = p4d_val(p4dp_get(leaf->entry));
		break;
	default:
		return false;
	}

	if (leaf->level != PGTABLE_LEVEL_PTE && !(val & _PAGE_LEAF))
		return false;

	leaf->pfn = __page_val_to_pfn(val);
	leaf->prot = __pgprot(val & ~_PAGE_PFN_MASK);

	return true;
}

void arch_cpa_write_leaf(struct cpa_req *req, struct cpa_leaf *leaf,
			 pgprot_t prot)
{
	cpa_set_entry(leaf->level, leaf->entry, cpa_mkval(leaf->pfn, prot));
}

/*
 * The old leaf and the new table map the same pfns with the same
 * attributes, so the TLB may hold either of them until arch_cpa_flush().
 */
int arch_cpa_split(struct cpa_req *req, struct cpa_leaf *leaf)
{
	/* tables at all levels have PTRS_PER_PTE entries */
	unsigned long step = (leaf->size / PTRS_PER_PTE) >> PAGE_SHIFT;
	enum pgtable_level level = leaf->level - 1;
	unsigned int i;
	pte_t *table;

	table = cpa_alloc_table(req, level, leaf->start);
	if (!table)
		return -ENOMEM;

	for (i = 0; i < PTRS_PER_PTE; i++)
		table[i] = __pte(cpa_mkval(leaf->pfn + i * step, leaf->prot));

	/* the walker must not see a partially filled table */
	smp_wmb();

	cpa_set_entry(leaf->level, leaf->entry,
		      cpa_mkval(virt_to_pfn(table), PAGE_TABLE));

	return 0;
}

void arch_cpa_flush(struct cpa_req *req)
{
	/* a change of a non-leaf entry requires SFENCE.VMA with rs1=x0 */
	if (req->changed & CPA_CHANGED_SPLIT) {
		flush_tlb_all();
		return;
	}

	/* RV32 page fault handler does not flush cached V=0 entries */
	if (!(req->flags & CPA_NOFLUSH) || !IS_ENABLED(CONFIG_64BIT)) {
		cpa_flush_ranges(req);
		return;
	}

#ifdef CONFIG_64BIT
	/* V=0 entries may be cached, let the page fault handler flush them */
	if (pgprot_val(req->set) & _PAGE_PRESENT)
		mark_new_valid_map();
#endif
}

int set_memory_rw_nx(unsigned long addr, int numpages)
{
	struct cpa_req req = {
		.addr = addr,
		.numpages = numpages,
	};

	if (numpages <= 0)
		return 0;

	cpa_req_add_op(&req, CPA_PROT_RW);
	cpa_req_add_op(&req, CPA_PROT_NX);

	return cpa_change(&req);
}

#ifdef CONFIG_DEBUG_PAGEALLOC
static int debug_pagealloc_set_page(pte_t *pte, unsigned long addr, void *data)
{
	int enable = *(int *)data;

	unsigned long val = pte_val(ptep_get(pte));

	if (enable)
		val |= _PAGE_PRESENT;
	else
		val &= ~_PAGE_PRESENT;

	set_pte(pte, __pte(val));

	return 0;
}

void __kernel_map_pages(struct page *page, int numpages, int enable)
{
	if (!debug_pagealloc_enabled())
		return;

	unsigned long start = (unsigned long)page_address(page);
	unsigned long size = PAGE_SIZE * numpages;

	apply_to_existing_page_range(&init_mm, start, size, debug_pagealloc_set_page, &enable);

	flush_tlb_kernel_range(start, start + size);
}
#endif
