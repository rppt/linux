// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019, 2020, Oracle and/or its affiliates.
 *
 */

#include <linux/slab.h>

#include <asm/dpt.h>

/*
 * Get the pointer to the beginning of a page table directory from a page
 * table directory entry.
 */
#define DPT_BACKEND_PAGE_ALIGN(entry)	\
	((typeof(entry))(((unsigned long)(entry)) & PAGE_MASK))

/*
 * Pages used to build a page-table are stored in the backend_pages XArray.
 * Each entry in the array is a logical OR of the page address and the page
 * table level (PTE, PMD, PUD, P4D) this page is used for in the page-table.
 *
 * As a page address is aligned with PAGE_SIZE, we have plenty of space
 * for storing the page table level (which is a value between 0 and 4) in
 * the low bits of the page address.
 *
 */

#define DPT_BACKEND_PAGE_ENTRY(addr, level)	\
	((typeof(addr))(((unsigned long)(addr)) | ((unsigned long)(level))))
#define DPT_BACKEND_PAGE_ADDR(entry)		\
	((void *)(((unsigned long)(entry)) & PAGE_MASK))
#define DPT_BACKEND_PAGE_LEVEL(entry)		\
	((enum page_table_level)(((unsigned long)(entry)) & ~PAGE_MASK))

static int dpt_add_backend_page(struct dpt *dpt, void *addr,
				enum page_table_level level)
{
	unsigned long index;
	void *old_entry;

	if ((!addr) || ((unsigned long)addr) & ~PAGE_MASK)
		return -EINVAL;

	lockdep_assert_held(&dpt->lock);
	index = dpt->backend_pages_count;

	old_entry = xa_store(&dpt->backend_pages, index,
			     DPT_BACKEND_PAGE_ENTRY(addr, level),
			     GFP_KERNEL);
	if (xa_is_err(old_entry))
		return xa_err(old_entry);
	if (old_entry)
		return -EBUSY;

	dpt->backend_pages_count++;

	return 0;
}

/*
 * Check if an offset in the page-table is valid, i.e. check that the
 * offset is on a page effectively belonging to the page-table.
 */
static bool dpt_valid_offset(struct dpt *dpt, void *offset)
{
	unsigned long index;
	void *addr, *entry;
	bool valid;

	addr = DPT_BACKEND_PAGE_ALIGN(offset);
	valid = false;

	lockdep_assert_held(&dpt->lock);
	xa_for_each(&dpt->backend_pages, index, entry) {
		if (DPT_BACKEND_PAGE_ADDR(entry) == addr) {
			valid = true;
			break;
		}
	}

	return valid;
}

/*
 * dpt_pXX_offset() functions are equivalent to kernel pXX_offset()
 * functions but, in addition, they ensure that page table pointers
 * are in the specified decorated page table. Otherwise an error is
 * returned.
 */

static pte_t *dpt_pte_offset(struct dpt *dpt,
			     pmd_t *pmd, unsigned long addr)
{
	pte_t *pte;

	pte = pte_offset_map(pmd, addr);
	if (!dpt_valid_offset(dpt, pte)) {
		pr_err("DPT %p: PTE %px not found\n", dpt, pte);
		return ERR_PTR(-EINVAL);
	}

	return pte;
}

static pmd_t *dpt_pmd_offset(struct dpt *dpt,
			     pud_t *pud, unsigned long addr)
{
	pmd_t *pmd;

	pmd = pmd_offset(pud, addr);
	if (!dpt_valid_offset(dpt, pmd)) {
		pr_err("DPT %p: PMD %px not found\n", dpt, pmd);
		return ERR_PTR(-EINVAL);
	}

	return pmd;
}

static pud_t *dpt_pud_offset(struct dpt *dpt,
			     p4d_t *p4d, unsigned long addr)
{
	pud_t *pud;

	pud = pud_offset(p4d, addr);
	if (!dpt_valid_offset(dpt, pud)) {
		pr_err("DPT %p: PUD %px not found\n", dpt, pud);
		return ERR_PTR(-EINVAL);
	}

	return pud;
}

static p4d_t *dpt_p4d_offset(struct dpt *dpt,
			     pgd_t *pgd, unsigned long addr)
{
	p4d_t *p4d;

	p4d = p4d_offset(pgd, addr);
	/*
	 * p4d is the same has pgd if we don't have a 5-level page table.
	 */
	if ((p4d != (p4d_t *)pgd) && !dpt_valid_offset(dpt, p4d)) {
		pr_err("DPT %p: P4D %px not found\n", dpt, p4d);
		return ERR_PTR(-EINVAL);
	}

	return p4d;
}

/*
 * dpt_create - allocate a page-table and create a corresponding
 * decorated page-table. The page-table is allocated and aligned
 * at the specified alignment (pgt_alignment) which should be a
 * multiple of PAGE_SIZE.
 */
struct dpt *dpt_create(unsigned int pgt_alignment)
{
	unsigned int alloc_order;
	unsigned long pagetable;
	struct dpt *dpt;

	if (!IS_ALIGNED(pgt_alignment, PAGE_SIZE))
		return NULL;

	alloc_order = round_up(PAGE_SIZE + pgt_alignment,
			       PAGE_SIZE) >> PAGE_SHIFT;

	dpt = kzalloc(sizeof(*dpt), GFP_KERNEL);
	if (!dpt)
		return NULL;

	pagetable = (unsigned long)__get_free_pages(GFP_KERNEL_ACCOUNT |
						    __GFP_ZERO,
						    alloc_order);
	if (!pagetable) {
		kfree(dpt);
		return NULL;
	}
	dpt->pagetable = (pgd_t *)(pagetable + pgt_alignment);
	dpt->alignment = pgt_alignment;

	spin_lock_init(&dpt->lock);
	xa_init(&dpt->backend_pages);

	return dpt;
}
EXPORT_SYMBOL(dpt_create);

void dpt_destroy(struct dpt *dpt)
{
	unsigned int pgt_alignment;
	unsigned int alloc_order;
	unsigned long index;
	void *entry;

	if (!dpt)
		return;

	if (dpt->backend_pages_count) {
		xa_for_each(&dpt->backend_pages, index, entry)
			free_page((unsigned long)DPT_BACKEND_PAGE_ADDR(entry));
	}

	if (dpt->pagetable) {
		pgt_alignment = dpt->alignment;
		alloc_order = round_up(PAGE_SIZE + pgt_alignment,
				       PAGE_SIZE) >> PAGE_SHIFT;
		free_pages((unsigned long)(dpt->pagetable) - pgt_alignment,
			   alloc_order);
	}

	kfree(dpt);
}
EXPORT_SYMBOL(dpt_destroy);
