// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2019 SiFive
 */

#include <linux/pageattr.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

void arch_cpa_prot(enum cpa_prot_op op, pgprot_t *set, pgprot_t *clr)
{
	unsigned long s = 0, c = 0;

	switch (op) {
	case CPA_PROT_RO:
		c = _PAGE_WRITE;
		break;
	case CPA_PROT_RW:
		/* W without R is reserved */
		s = _PAGE_READ | _PAGE_WRITE;
		break;
	case CPA_PROT_X:
		s = _PAGE_EXEC;
		break;
	case CPA_PROT_NX:
		c = _PAGE_EXEC;
		break;
	case CPA_PROT_NP:
	case CPA_PROT_INVALID:
		c = _PAGE_PRESENT;
		break;
	case CPA_PROT_P:
		s = _PAGE_PRESENT;
		break;
	case CPA_PROT_DEFAULT:
		s = pgprot_val(PAGE_KERNEL);
		c = _PAGE_EXEC;
		break;
	}

	*set = __pgprot(s);
	*clr = __pgprot(c);
}

static unsigned long cpa_entry_val(struct cpa_leaf *leaf)
{
	switch (leaf->level) {
	case PGTABLE_LEVEL_PTE:
		return pte_val(ptep_get(leaf->entry));
	case PGTABLE_LEVEL_PMD:
		return pmd_val(pmdp_get(leaf->entry));
	case PGTABLE_LEVEL_PUD:
		return pud_val(pudp_get(leaf->entry));
	default:
		return p4d_val(p4dp_get(leaf->entry));
	}
}

static void cpa_set_entry(struct cpa_leaf *leaf, unsigned long val)
{
	switch (leaf->level) {
	case PGTABLE_LEVEL_PTE:
		set_pte(leaf->entry, __pte(val));
		break;
	case PGTABLE_LEVEL_PMD:
		set_pmd(leaf->entry, __pmd(val));
		break;
	case PGTABLE_LEVEL_PUD:
		set_pud(leaf->entry, __pud(val));
		break;
	default:
		set_p4d(leaf->entry, __p4d(val));
		break;
	}
}

static unsigned long cpa_mkval(unsigned long pfn, pgprot_t prot)
{
	return (pfn << _PAGE_PFN_SHIFT) | pgprot_val(prot);
}

/* Leaves have the same format at all levels */
void arch_cpa_read_leaf(struct cpa_leaf *leaf)
{
	unsigned long val = cpa_entry_val(leaf);

#ifdef CONFIG_RISCV_ISA_SVNAPOT
	if (leaf->level == PGTABLE_LEVEL_PTE && has_svnapot() &&
	    pte_napot(__pte(val))) {
		pte_t *ptep = leaf->entry;

		leaf->nr = napot_pte_num(napot_cont_order(__pte(val)));
		leaf->pfn = pte_pfn(__pte(val)) +
			    ((unsigned long)ptep / sizeof(*ptep) & (leaf->nr - 1));
		leaf->prot = __pgprot(val & ~(_PAGE_PFN_MASK | _PAGE_NAPOT));
		return;
	}
#endif

	leaf->pfn = (val & _PAGE_PFN_MASK) >> _PAGE_PFN_SHIFT;
	leaf->prot = __pgprot(val & ~_PAGE_PFN_MASK);
}

void arch_cpa_write_leaf(struct cpa_req *req, struct cpa_leaf *leaf,
			 pgprot_t prot)
{
	unsigned long val = cpa_mkval(leaf->pfn, prot);

#ifdef CONFIG_64BIT
	/* V=0 entries may be cached, let the fault handler flush them */
	if ((req->flags & CPA_NOFLUSH) && (pgprot_val(prot) & _PAGE_PRESENT) &&
	    !(pgprot_val(leaf->prot) & _PAGE_PRESENT))
		mark_new_valid_map();
#endif

#ifdef CONFIG_RISCV_ISA_SVNAPOT
	if (leaf->nr > 1) {
		pte_t pte = pte_mknapot(__pte(val), ilog2(leaf->nr));
		pte_t *ptep = leaf->entry;
		unsigned int i;

		for (i = 0; i < leaf->nr; i++)
			set_pte(ptep + i, pte);
		return;
	}
#endif

	cpa_set_entry(leaf, val);
}

/*
 * The old leaf and the new table map the same pfns with the same
 * attributes, so they may be used at the same time. Changing a non-leaf
 * entry requires a full SFENCE.VMA before the smaller leaves are changed.
 */
int arch_cpa_split(struct cpa_req *req, struct cpa_leaf *leaf, void *table)
{
	unsigned long step = (leaf->size / PTRS_PER_PTE) >> PAGE_SHIFT;
	pte_t *ptep = table;
	unsigned int i;

	for (i = 0; i < PTRS_PER_PTE; i++)
		set_pte(ptep + i, __pte(cpa_mkval(leaf->pfn + i * step,
						  leaf->prot)));

	/* the walker must not see a partially filled table */
	smp_wmb();

	cpa_set_entry(leaf, cpa_mkval(virt_to_pfn(table),
				      __pgprot(_PAGE_TABLE)));
	flush_tlb_all();

	return 0;
}

int arch_cpa_split_group(struct cpa_req *req, struct cpa_leaf *leaf)
{
	pte_t *ptep = leaf->entry;
	unsigned int i;

	if (req->flags & CPA_ATOMIC)
		return -EOPNOTSUPP;

	for (i = 0; i < leaf->nr; i++)
		set_pte(ptep + i, __pte(cpa_mkval(leaf->pfn + i, leaf->prot)));

	flush_tlb_kernel_range(leaf->start, leaf->start + leaf->size);

	return 0;
}

/* The table must not be freed before a full SFENCE.VMA on all harts */
bool arch_cpa_collapse(struct cpa_req *req, struct cpa_leaf *leaf)
{
	cpa_set_entry(leaf, cpa_mkval(leaf->pfn, leaf->prot));
	flush_tlb_all();

	return true;
}

/* The direct map alias of kernel image and vmalloc is never executable */
bool arch_cpa_get_alias(struct cpa_req *req, struct cpa_range *range,
			unsigned long addr, unsigned long pfn,
			unsigned long nr, unsigned int idx,
			struct cpa_range *alias)
{
	if (idx || is_linear_mapping(addr))
		return false;

	if (!pfn_valid(pfn) || !pfn_valid(pfn + nr - 1))
		return false;

	alias->start = (unsigned long)__va(PFN_PHYS(pfn));
	alias->end = alias->start + nr * PAGE_SIZE;
	alias->set = __pgprot(pgprot_val(range->set) & ~_PAGE_EXEC);
	alias->clr = range->clr;

	return true;
}

int set_memory_rw_nx(unsigned long addr, int numpages)
{
	struct cpa_req req = {
		.addr = addr,
		.numpages = numpages,
		.set = __pgprot(_PAGE_READ | _PAGE_WRITE),
		.clr = __pgprot(_PAGE_EXEC),
	};

	if (numpages <= 0)
		return 0;

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
