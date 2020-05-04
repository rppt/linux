// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019, 2020, Oracle and/or its affiliates.
 *
 */

#include <linux/mm.h>
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
 * dpt_pXX_alloc() functions are equivalent to kernel pXX_alloc() functions
 * but, in addition, they keep track of new pages allocated for the specified
 * decorated page-table.
 */

static pte_t *dpt_pte_alloc(struct dpt *dpt, pmd_t *pmd, unsigned long addr)
{
	struct page *page;
	pte_t *pte;
	int err;

	if (pmd_none(*pmd)) {
		page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!page)
			return ERR_PTR(-ENOMEM);
		pte = (pte_t *)page_address(page);
		err = dpt_add_backend_page(dpt, pte, PGT_LEVEL_PTE);
		if (err) {
			free_page((unsigned long)pte);
			return ERR_PTR(err);
		}
		set_pmd_safe(pmd, __pmd(__pa(pte) | _KERNPG_TABLE));
		pte = pte_offset_map(pmd, addr);
	} else {
		pte = dpt_pte_offset(dpt, pmd,  addr);
	}

	return pte;
}

static pmd_t *dpt_pmd_alloc(struct dpt *dpt, pud_t *pud, unsigned long addr)
{
	struct page *page;
	pmd_t *pmd;
	int err;

	if (pud_none(*pud)) {
		page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!page)
			return ERR_PTR(-ENOMEM);
		pmd = (pmd_t *)page_address(page);
		err = dpt_add_backend_page(dpt, pmd, PGT_LEVEL_PMD);
		if (err) {
			free_page((unsigned long)pmd);
			return ERR_PTR(err);
		}
		set_pud_safe(pud, __pud(__pa(pmd) | _KERNPG_TABLE));
		pmd = pmd_offset(pud, addr);
	} else {
		pmd = dpt_pmd_offset(dpt, pud, addr);
	}

	return pmd;
}

static pud_t *dpt_pud_alloc(struct dpt *dpt, p4d_t *p4d, unsigned long addr)
{
	struct page *page;
	pud_t *pud;
	int err;

	if (p4d_none(*p4d)) {
		page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!page)
			return ERR_PTR(-ENOMEM);
		pud = (pud_t *)page_address(page);
		err = dpt_add_backend_page(dpt, pud, PGT_LEVEL_PUD);
		if (err) {
			free_page((unsigned long)pud);
			return ERR_PTR(err);
		}
		set_p4d_safe(p4d, __p4d(__pa(pud) | _KERNPG_TABLE));
		pud = pud_offset(p4d, addr);
	} else {
		pud = dpt_pud_offset(dpt, p4d, addr);
	}

	return pud;
}

static p4d_t *dpt_p4d_alloc(struct dpt *dpt, pgd_t *pgd, unsigned long addr)
{
	struct page *page;
	p4d_t *p4d;
	int err;

	if (!pgtable_l5_enabled())
		return (p4d_t *)pgd;

	if (pgd_none(*pgd)) {
		page = alloc_page(GFP_KERNEL | __GFP_ZERO);
		if (!page)
			return ERR_PTR(-ENOMEM);
		p4d = (p4d_t *)page_address(page);
		err = dpt_add_backend_page(dpt, p4d, PGT_LEVEL_P4D);
		if (err) {
			free_page((unsigned long)p4d);
			return ERR_PTR(err);
		}
		set_pgd_safe(pgd, __pgd(__pa(p4d) | _KERNPG_TABLE));
		p4d = p4d_offset(pgd, addr);
	} else {
		p4d = dpt_p4d_offset(dpt, pgd, addr);
	}

	return p4d;
}

/*
 * dpt_set_pXX() functions are equivalent to kernel set_pXX() functions
 * but, in addition, they ensure that they are not overwriting an already
 * existing reference in the decorated page table. Otherwise an error is
 * returned.
 */

static int dpt_set_pte(struct dpt *dpt, pte_t *pte, pte_t pte_value)
{
#ifdef DEBUG
	/*
	 * The pte pointer should come from dpt_pte_alloc() or dpt_pte_offset()
	 * both of which check if the pointer is in the decorated page table.
	 * So this is a paranoid check to ensure the pointer is really in the
	 * decorated page table.
	 */
	if (!dpt_valid_offset(dpt, pte)) {
		pr_err("DPT %p: PTE %px not found\n", dpt, pte);
		return -EINVAL;
	}
#endif
	set_pte(pte, pte_value);

	return 0;
}

static int dpt_set_pmd(struct dpt *dpt, pmd_t *pmd, pmd_t pmd_value)
{
#ifdef DEBUG
	/*
	 * The pmd pointer should come from dpt_pmd_alloc() or dpt_pmd_offset()
	 * both of which check if the pointer is in the decorated page table.
	 * So this is a paranoid check to ensure the pointer is really in the
	 * decorated page table.
	 */
	if (!dpt_valid_offset(dpt, pmd)) {
		pr_err("DPT %p: PMD %px not found\n", dpt, pmd);
		return -EINVAL;
	}
#endif
	if (pmd_val(*pmd) == pmd_val(pmd_value))
		return 0;

	if (!pmd_none(*pmd)) {
		pr_err("DPT %p: PMD %px overwriting %lx with %lx\n",
		       dpt, pmd, pmd_val(*pmd), pmd_val(pmd_value));
		return -EBUSY;
	}

	set_pmd(pmd, pmd_value);

	return 0;
}

static int dpt_set_pud(struct dpt *dpt, pud_t *pud, pud_t pud_value)
{
#ifdef DEBUG
	/*
	 * The pud pointer should come from dpt_pud_alloc() or dpt_pud_offset()
	 * both of which check if the pointer is in the decorated page table.
	 * So this is a paranoid check to ensure the pointer is really in the
	 * decorated page table.
	 */
	if (!dpt_valid_offset(dpt, pud)) {
		pr_err("DPT %p: PUD %px not found\n", dpt, pud);
		return -EINVAL;
	}
#endif
	if (pud_val(*pud) == pud_val(pud_value))
		return 0;

	if (!pud_none(*pud)) {
		pr_err("DPT %p: PUD %px overwriting %lx with %lx\n",
		       dpt, pud, pud_val(*pud), pud_val(pud_value));
		return -EBUSY;
	}

	set_pud(pud, pud_value);

	return 0;
}

static int dpt_set_p4d(struct dpt *dpt, p4d_t *p4d, p4d_t p4d_value)
{
#ifdef DEBUG
	/*
	 * The p4d pointer should come from dpt_p4d_alloc() or dpt_p4d_offset()
	 * both of which check if the pointer is in the decorated page table.
	 * So this is a paranoid check to ensure the pointer is really in the
	 * decorated page table.
	 */
	if (!dpt_valid_offset(dpt, p4d)) {
		pr_err("DPT %p: P4D %px not found\n", dpt, p4d);
		return -EINVAL;
	}
#endif
	if (p4d_val(*p4d) == p4d_val(p4d_value))
		return 0;

	if (!p4d_none(*p4d)) {
		pr_err("DPT %p: P4D %px overwriting %lx with %lx\n",
		       dpt, p4d, p4d_val(*p4d), p4d_val(p4d_value));
		return -EBUSY;
	}

	set_p4d(p4d, p4d_value);

	return 0;
}

static int dpt_set_pgd(struct dpt *dpt, pgd_t *pgd, pgd_t pgd_value)
{
	if (pgd_val(*pgd) == pgd_val(pgd_value))
		return 0;

	if (!pgd_none(*pgd)) {
		pr_err("DPT %p: PGD %px overwriting %lx with %lx\n",
		       dpt, pgd, pgd_val(*pgd), pgd_val(pgd_value));
		return -EBUSY;
	}

	set_pgd(pgd, pgd_value);

	return 0;
}

static int dpt_copy_pte_range(struct dpt *dpt, pmd_t *dst_pmd, pmd_t *src_pmd,
			      unsigned long addr, unsigned long end)
{
	pte_t *src_pte, *dst_pte;

	dst_pte = dpt_pte_alloc(dpt, dst_pmd, addr);
	if (IS_ERR(dst_pte))
		return PTR_ERR(dst_pte);

	addr &= PAGE_MASK;
	src_pte = pte_offset_map(src_pmd, addr);

	do {
		dpt_set_pte(dpt, dst_pte, *src_pte);

	} while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr < end);

	return 0;
}

static int dpt_copy_pmd_range(struct dpt *dpt, pud_t *dst_pud, pud_t *src_pud,
			      unsigned long addr, unsigned long end,
			      enum page_table_level level)
{
	pmd_t *src_pmd, *dst_pmd;
	unsigned long next;
	int err;

	dst_pmd = dpt_pmd_alloc(dpt, dst_pud, addr);
	if (IS_ERR(dst_pmd))
		return PTR_ERR(dst_pmd);

	src_pmd = pmd_offset(src_pud, addr);

	do {
		next = pmd_addr_end(addr, end);
		if (level == PGT_LEVEL_PMD || pmd_none(*src_pmd) ||
		    pmd_trans_huge(*src_pmd) || pmd_devmap(*src_pmd)) {
			err = dpt_set_pmd(dpt, dst_pmd, *src_pmd);
			if (err)
				return err;
			continue;
		}

		if (!pmd_present(*src_pmd)) {
			pr_warn("DPT %p: PMD not present for [%lx,%lx]\n",
				dpt, addr, next - 1);
			pmd_clear(dst_pmd);
			continue;
		}

		err = dpt_copy_pte_range(dpt, dst_pmd, src_pmd, addr, next);
		if (err) {
			pr_err("DPT %p: PMD error copying PTE addr=%lx next=%lx\n",
			       dpt, addr, next);
			return err;
		}

	} while (dst_pmd++, src_pmd++, addr = next, addr < end);

	return 0;
}

static int dpt_copy_pud_range(struct dpt *dpt, p4d_t *dst_p4d, p4d_t *src_p4d,
			      unsigned long addr, unsigned long end,
			      enum page_table_level level)
{
	pud_t *src_pud, *dst_pud;
	unsigned long next;
	int err;

	dst_pud = dpt_pud_alloc(dpt, dst_p4d, addr);
	if (IS_ERR(dst_pud))
		return PTR_ERR(dst_pud);

	src_pud = pud_offset(src_p4d, addr);

	do {
		next = pud_addr_end(addr, end);
		if (level == PGT_LEVEL_PUD || pud_none(*src_pud) ||
		    pud_trans_huge(*src_pud) || pud_devmap(*src_pud)) {
			err = dpt_set_pud(dpt, dst_pud, *src_pud);
			if (err)
				return err;
			continue;
		}

		err = dpt_copy_pmd_range(dpt, dst_pud, src_pud, addr, next,
					 level);
		if (err) {
			pr_err("DPT %p: PUD error copying PMD addr=%lx next=%lx\n",
			       dpt, addr, next);
			return err;
		}

	} while (dst_pud++, src_pud++, addr = next, addr < end);

	return 0;
}

static int dpt_copy_p4d_range(struct dpt *dpt, pgd_t *dst_pgd, pgd_t *src_pgd,
			      unsigned long addr, unsigned long end,
			      enum page_table_level level)
{
	p4d_t *src_p4d, *dst_p4d;
	unsigned long next;
	int err;

	dst_p4d = dpt_p4d_alloc(dpt, dst_pgd, addr);
	if (IS_ERR(dst_p4d))
		return PTR_ERR(dst_p4d);

	src_p4d = p4d_offset(src_pgd, addr);

	do {
		next = p4d_addr_end(addr, end);
		if (level == PGT_LEVEL_P4D || p4d_none(*src_p4d)) {
			err = dpt_set_p4d(dpt, dst_p4d, *src_p4d);
			if (err)
				return err;
			continue;
		}

		err = dpt_copy_pud_range(dpt, dst_p4d, src_p4d, addr, next,
					 level);
		if (err) {
			pr_err("DPT %p: P4D error copying PUD addr=%lx next=%lx\n",
			       dpt, addr, next);
			return err;
		}

	} while (dst_p4d++, src_p4d++, addr = next, addr < end);

	return 0;
}

static int dpt_copy_pgd_range(struct dpt *dpt,
			      pgd_t *dst_pagetable, pgd_t *src_pagetable,
			      unsigned long addr, unsigned long end,
			      enum page_table_level level)
{
	pgd_t *src_pgd, *dst_pgd;
	unsigned long next;
	int err;

	dst_pgd = pgd_offset_pgd(dst_pagetable, addr);
	src_pgd = pgd_offset_pgd(src_pagetable, addr);

	do {
		next = pgd_addr_end(addr, end);
		if (level == PGT_LEVEL_PGD || pgd_none(*src_pgd)) {
			err = dpt_set_pgd(dpt, dst_pgd, *src_pgd);
			if (err)
				return err;
			continue;
		}

		err = dpt_copy_p4d_range(dpt, dst_pgd, src_pgd, addr, next,
					 level);
		if (err) {
			pr_err("DPT %p: PGD error copying P4D addr=%lx next=%lx\n",
			       dpt, addr, next);
			return err;
		}

	} while (dst_pgd++, src_pgd++, addr = next, addr < end);

	return 0;
}

/*
 * Copy page table entries from the current page table (i.e. from the
 * kernel page table) to the specified decorated page-table. The level
 * parameter specifies the page-table level (PGD, P4D, PUD PMD, PTE)
 * at which the copy should be done.
 */
int dpt_map_range(struct dpt *dpt, void *ptr, size_t size,
		  enum page_table_level level)
{
	unsigned long addr = (unsigned long)ptr;
	unsigned long end = addr + ((unsigned long)size);
	unsigned long flags;
	int err;

	pr_debug("DPT %p: MAP %px/%lx/%d\n", dpt, ptr, size, level);

	spin_lock_irqsave(&dpt->lock, flags);
	err = dpt_copy_pgd_range(dpt, dpt->pagetable, current->mm->pgd,
				 addr, end, level);
	spin_unlock_irqrestore(&dpt->lock, flags);

	return err;
}
EXPORT_SYMBOL(dpt_map_range);

/*
 * Copy page-table PTE entries from the current page-table to the
 * specified decorated page-table.
 */
int dpt_map(struct dpt *dpt, void *ptr, unsigned long size)
{
	return dpt_map_range(dpt, ptr, size, PGT_LEVEL_PTE);
}
EXPORT_SYMBOL(dpt_map);

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
