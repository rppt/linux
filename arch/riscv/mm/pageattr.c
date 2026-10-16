// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2019 SiFive
 */

#include <linux/mm.h>
#include <linux/pageattr.h>
#include <linux/pgtable.h>
#include <linux/set_memory.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>

/* A leaf of the kernel page table, all levels share the entry format */
struct cpa_leaf {
	void *entry;
	unsigned long val;
	enum pgtable_level level;
};

static bool cpa_leaf_init(struct cpa_leaf *leaf, void *entry, unsigned long val,
			  enum pgtable_level level)
{
	leaf->entry = entry;
	leaf->val = val;
	leaf->level = level;

	return true;
}

/*
 * A non-present entry above the PTE level that is not none is a leaf,
 * because entries that point to a table are always present.
 */
static bool cpa_lookup_leaf(unsigned long addr, struct cpa_leaf *leaf)
{
	pgd_t *pgd;
	p4d_t *p4d, p4dv;
	pud_t *pud, pudv;
	pmd_t *pmd, pmdv;
	pte_t *pte;

	pgd = pgd_offset_k(addr);
	if (pgd_none(pgdp_get(pgd)))
		return false;

	p4d = p4d_offset(pgd, addr);
	p4dv = p4dp_get(p4d);
	if (p4d_none(p4dv))
		return false;
	if (p4d_leaf(p4dv) || !p4d_present(p4dv))
		return cpa_leaf_init(leaf, p4d, p4d_val(p4dv), PGTABLE_LEVEL_P4D);

	pud = pud_offset(p4d, addr);
	pudv = pudp_get(pud);
	if (pud_none(pudv))
		return false;
	if (pud_leaf(pudv) || !pud_present(pudv))
		return cpa_leaf_init(leaf, pud, pud_val(pudv), PGTABLE_LEVEL_PUD);

	pmd = pmd_offset(pud, addr);
	pmdv = pmdp_get(pmd);
	if (pmd_none(pmdv))
		return false;
	if (pmd_leaf(pmdv) || !pmd_present(pmdv))
		return cpa_leaf_init(leaf, pmd, pmd_val(pmdv), PGTABLE_LEVEL_PMD);

	pte = pte_offset_kernel(pmd, addr);
	if (pte_none(ptep_get(pte)))
		return false;

	return cpa_leaf_init(leaf, pte, pte_val(ptep_get(pte)), PGTABLE_LEVEL_PTE);
}

static void cpa_set_leaf(struct cpa_leaf *leaf, unsigned long val)
{
	switch (leaf->level) {
	case PGTABLE_LEVEL_P4D:
		set_p4d(leaf->entry, __p4d(val));
		break;
	case PGTABLE_LEVEL_PUD:
		set_pud(leaf->entry, __pud(val));
		break;
	case PGTABLE_LEVEL_PMD:
		set_pmd(leaf->entry, __pmd(val));
		break;
	default:
		set_pte(leaf->entry, __pte(val));
		break;
	}
}

static unsigned long cpa_leaf_size(enum pgtable_level level)
{
	switch (level) {
	case PGTABLE_LEVEL_P4D:
		return P4D_SIZE;
	case PGTABLE_LEVEL_PUD:
		return PUD_SIZE;
	case PGTABLE_LEVEL_PMD:
		return PMD_SIZE;
	default:
		return PAGE_SIZE;
	}
}

static void *cpa_alloc_table(enum pgtable_level level, unsigned long addr)
{
	switch (level) {
	case PGTABLE_LEVEL_P4D:
		return pud_alloc_one(&init_mm, addr);
	case PGTABLE_LEVEL_PUD:
		return pmd_alloc_one(&init_mm, addr);
	default:
		return pte_alloc_one_kernel(&init_mm);
	}
}

static void cpa_free_table(enum pgtable_level level, void *table)
{
	switch (level) {
	case PGTABLE_LEVEL_P4D:
		pud_free(&init_mm, table);
		break;
	case PGTABLE_LEVEL_PUD:
		pmd_free(&init_mm, table);
		break;
	default:
		pte_free_kernel(&init_mm, table);
		break;
	}
}

static void cpa_fill_table(struct cpa_leaf *leaf, void *table)
{
	unsigned long pfn = __page_val_to_pfn(leaf->val);
	pgprot_t prot = __pgprot(leaf->val & ~_PAGE_PFN_MASK);
	int i;

	switch (leaf->level) {
#ifdef CONFIG_64BIT
	case PGTABLE_LEVEL_P4D:
		for (i = 0; i < PTRS_PER_PUD; i++)
			set_pud((pud_t *)table + i,
				pfn_pud(pfn + i * (PUD_SIZE >> PAGE_SHIFT), prot));
		break;
	case PGTABLE_LEVEL_PUD:
		for (i = 0; i < PTRS_PER_PMD; i++)
			set_pmd((pmd_t *)table + i,
				pfn_pmd(pfn + i * (PMD_SIZE >> PAGE_SHIFT), prot));
		break;
#endif
	default:
		for (i = 0; i < PTRS_PER_PTE; i++)
			set_pte((pte_t *)table + i, pfn_pte(pfn + i, prot));
		break;
	}
}

static int cpa_split_leaf(struct cpa_data *cpa, unsigned long addr,
			  struct cpa_leaf *leaf)
{
	pgd_t *pgd = leaf->entry;
	struct cpa_leaf cur;
	void *table;

	/* Kernel PGD entries are copied to every PGD and are not kept in sync */
	if (WARN_ON_ONCE(pgd >= init_mm.pgd && pgd < init_mm.pgd + PTRS_PER_PGD))
		return -EINVAL;

	cpa_unlock(cpa);
	table = cpa_alloc_table(leaf->level, addr);
	cpa_relock(cpa);
	if (!table)
		return -ENOMEM;

	if (!cpa_lookup_leaf(addr, &cur) || cur.entry != leaf->entry ||
	    cur.val != leaf->val) {
		cpa_free_table(leaf->level, table);
		return 1;
	}

	cpa_fill_table(leaf, table);
	/* Make the new table visible before the entry that points to it */
	smp_wmb();
	cpa_set_leaf(leaf, (virt_to_pfn(table) << _PAGE_PFN_SHIFT) | _PAGE_TABLE);

	/* The stale TLB entries of the large leaf are not bounded by the range */
	cpa->state |= CPA_ST_FLUSHTLB | CPA_ST_FLUSHTLB_ALL;

	return 1;
}

static unsigned long cpa_new_val(struct cpa_data *cpa, unsigned long val)
{
	return (val & ~pgprot_val(cpa->mask_clr)) | pgprot_val(cpa->mask_set);
}

/*
 * Split a large leaf unless the change covers all of it or does not change
 * it at all. Returns 1 if the leaf has to be looked up again.
 */
static int cpa_change_large_leaf(struct cpa_data *cpa, unsigned long addr,
				 struct cpa_leaf *leaf)
{
	unsigned long size = cpa_leaf_size(leaf->level);
	unsigned long offset = (addr & (size - 1)) >> PAGE_SHIFT;
	unsigned long nr = (size >> PAGE_SHIFT) - offset;
	unsigned long val = cpa_new_val(cpa, leaf->val);

	if (cpa->req & CPA_REQ_SPLIT ||
	    (val != leaf->val && (offset || cpa->numpages < nr)))
		return cpa_split_leaf(cpa, addr, leaf);

	if (val != leaf->val) {
		cpa_set_leaf(leaf, val);
		cpa->state |= CPA_ST_FLUSHTLB;
	}

	cpa->numpages = min(cpa->numpages, nr);
	cpa->pfn = __page_val_to_pfn(leaf->val) + offset;

	return 0;
}

int arch_change_page_attr(struct cpa_data *cpa)
{
	unsigned long addr = __cpa_addr(cpa, cpa->curpage);
	struct cpa_leaf leaf;
	unsigned long val;
	int ret;

	for (;;) {
		if (!cpa_lookup_leaf(addr, &leaf)) {
			/* An alias may legitimately be unmapped */
			if (cpa->state & CPA_ST_ALIAS) {
				cpa->numpages = 1;
				return 0;
			}

			VM_WARN_ONCE(1, "CPA: no mapping for %lx\n", addr);
			return -EFAULT;
		}

		if (leaf.level == PGTABLE_LEVEL_PTE)
			break;

		ret = cpa_change_large_leaf(cpa, addr, &leaf);
		if (ret <= 0)
			return ret;
	}

	val = cpa_new_val(cpa, leaf.val);
	if (val != leaf.val) {
		cpa_set_leaf(&leaf, val);
		cpa->state |= CPA_ST_FLUSHTLB;
	}

	cpa->numpages = 1;
	cpa->pfn = __page_val_to_pfn(leaf.val);

	return 0;
}

int arch_cpa_op_desc(enum cpa_op op, struct cpa_op_desc *desc)
{
	unsigned long set = 0, clr = 0;
	unsigned int req = 0;

	switch (op) {
	case CPA_SET_RO:
		set = _PAGE_READ;
		clr = _PAGE_WRITE;
		break;
	case CPA_SET_RW:
		set = _PAGE_READ | _PAGE_WRITE;
		break;
	case CPA_SET_X:
		set = _PAGE_EXEC;
		break;
	case CPA_SET_NX:
		clr = _PAGE_EXEC;
		break;
	case CPA_SET_DEFAULT:
		set = pgprot_val(PAGE_KERNEL);
		clr = _PAGE_EXEC;
		req = CPA_REQ_NO_ALIAS;
		break;
	case CPA_SET_INVALID:
		clr = _PAGE_PRESENT;
		req = CPA_REQ_NO_ALIAS;
		break;
	default:
		return -EINVAL;
	}

	desc->mask_set = __pgprot(set);
	desc->mask_clr = __pgprot(clr);
	desc->req = req;

	return 0;
}

/*
 * Permission changes of vmalloc and kernel image addresses apply to their
 * linear mapping alias as well.
 */
int arch_cpa_aliases(struct cpa_data *cpa, unsigned long vaddr,
		     struct cpa_alias *aliases)
{
	if (is_linear_mapping(vaddr) || !pfn_valid(cpa->pfn))
		return 0;

	aliases[0].addr = (unsigned long)__va(PFN_PHYS(cpa->pfn));
	/* The linear mapping is never executable */
	aliases[0].keep = __pgprot(_PAGE_EXEC);
	aliases[0].ignore_err = false;

	return 1;
}

int set_memory_rw_nx(unsigned long addr, int numpages)
{
	return change_page_attr_set_clr(&addr, numpages,
					__pgprot(_PAGE_READ | _PAGE_WRITE),
					__pgprot(_PAGE_EXEC), 0, NULL);
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

bool kernel_page_present(struct page *page)
{
	unsigned long addr = (unsigned long)page_address(page);
	pgd_t *pgd;
	pud_t *pud;
	p4d_t *p4d;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset_k(addr);
	if (!pgd_present(pgdp_get(pgd)))
		return false;
	if (pgd_leaf(pgdp_get(pgd)))
		return true;

	p4d = p4d_offset(pgd, addr);
	if (!p4d_present(p4dp_get(p4d)))
		return false;
	if (p4d_leaf(p4dp_get(p4d)))
		return true;

	pud = pud_offset(p4d, addr);
	if (!pud_present(pudp_get(pud)))
		return false;
	if (pud_leaf(pudp_get(pud)))
		return true;

	pmd = pmd_offset(pud, addr);
	if (!pmd_present(pmdp_get(pmd)))
		return false;
	if (pmd_leaf(pmdp_get(pmd)))
		return pmd_val(pmdp_get(pmd)) & _PAGE_PRESENT;

	/* pte_present() is true for PAGE_KERNEL with _PAGE_PRESENT cleared */
	pte = pte_offset_kernel(pmd, addr);
	return pte_val(ptep_get(pte)) & _PAGE_PRESENT;
}
