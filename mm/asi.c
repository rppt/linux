// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/sizes.h>
#include <linux/random.h>
#include <linux/cpu.h>
#include <linux/asi.h>
#include <linux/page_excl.h>

#include <asm/pgalloc.h>

#undef pr_fmt
#define pr_fmt(fmt)     "ASI: " fmt

#define ASI_PRIVATE_PT 0xacacacacacacacac;

static bool asi_private_pt(struct page *page)
{
	return page->_pt_pad_2 == ASI_PRIVATE_PT;
}

static void asi_set_private_pt(struct page *page)
{
	page->_pt_pad_2 = ASI_PRIVATE_PT;
}

static void asi_clear_private_pt(struct page *page)
{
	page->_pt_pad_2 = 0;
}

static void asi_free_pte_range(struct mm_struct *mm, pmd_t *pmd)
{
	pte_t *pte, *ptep = pte_offset_kernel(pmd, 0);
	struct page *page;
	int i;

	page = pmd_page(*pmd);
	if (!asi_private_pt(page))
		return;

	for (i = 0, pte = ptep; i < PTRS_PER_PTE; i++, pte++)
		if (pte_present(*pte)) {
			struct page *p = pfn_to_page(pte_pfn(*pte));
			if (PageExclusive(p))
				page_unmake_exclusive(p, 0);
		}

	asi_clear_private_pt(page);
	pmd_clear(pmd);
	pte_free(mm, virt_to_page(ptep));
	mm_dec_nr_ptes(mm);
}

static void asi_free_pmd_range(struct mm_struct *mm, pud_t *pud)
{
	pmd_t *pmd, *pmdp;
	struct page *page;
	int i;

	pmdp = pmd_offset(pud, 0);

	for (i = 0, pmd = pmdp; i < PTRS_PER_PMD; i++, pmd++)
		if (!pmd_none(*pmd) && !pmd_large(*pmd))
			asi_free_pte_range(mm, pmd);

	page = pud_page(*pud);
	if (!asi_private_pt(page))
		return;

	asi_clear_private_pt(page);
	pud_clear(pud);
	pmd_free(mm, pmdp);
	mm_dec_nr_pmds(mm);
}

static void asi_free_pud_range(struct mm_struct *mm, p4d_t *p4d)
{
	pud_t *pud, *pudp;
	struct page *page;
	int i;

	pudp = pud_offset(p4d, 0);

	for (i = 0, pud = pudp; i < PTRS_PER_PUD; i++, pud++)
		if (!pud_none(*pud))
			asi_free_pmd_range(mm, pud);

	page = p4d_page(*p4d);
	if (!asi_private_pt(page))
		return;

	asi_clear_private_pt(page);
	p4d_clear(p4d);
	pud_free(mm, pudp);
	mm_dec_nr_puds(mm);
}

static void asi_free_p4d_range(struct mm_struct *mm, pgd_t *pgd)
{
	p4d_t *p4d, *p4dp;
	struct page *page;
	int i;

	p4dp = p4d_offset(pgd, 0);

	for (i = 0, p4d = p4dp; i < PTRS_PER_P4D; i++, p4d++)
		if (!p4d_none(*p4d))
			asi_free_pud_range(mm, p4d);

	page = pgd_page(*pgd);
	if (!asi_private_pt(page))
		return;

	asi_clear_private_pt(page);
	pgd_clear(pgd);
	p4d_free(mm, p4dp);
}

static int asi_free_pagetable(struct mm_struct *mm)
{
	pgd_t *pgd, *pgdp = mm->pgd;

	for (pgd = pgdp + KERNEL_PGD_BOUNDARY; pgd < pgdp + PTRS_PER_PGD; pgd++)
		if (!pgd_none(*pgd))
			asi_free_p4d_range(mm, pgd);


	return 0;
}

int asi_mm_init(struct mm_struct *mm)
{
	struct asi_ctx *asi_ctx;

	asi_ctx = kzalloc(sizeof(*asi_ctx), GFP_KERNEL);
	if (!asi_ctx)
		return -ENOMEM;

	asi_ctx->mm = mm;
	asi_ctx->pgd = mm->pgd;
	mm->asi_ctx = asi_ctx;

	return 0;
}

void asi_mm_fini(struct mm_struct *mm)
{
	kfree(mm->asi_ctx);
}

void asi_exit(struct mm_struct *mm)
{
	asi_free_pagetable(mm);
	asi_mm_fini(mm);
}

static int asi_clone_pte_range(struct mm_struct *dst_mm,
			       pmd_t *dst_pmd, pmd_t *src_pmd,
			       unsigned long addr, unsigned long end)
{
	pte_t *src_pte, *dst_pte;

	dst_pte = pte_alloc_map(dst_mm, dst_pmd, addr);
	if (!dst_pte)
		return -ENOMEM;

	asi_set_private_pt(pmd_page(*dst_pmd));

	addr &= PAGE_MASK;
	src_pte = pte_offset_map(src_pmd, addr);

	do {
		set_pte(dst_pte, *src_pte);
	} while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr < end);

	return 0;
}

static int asi_clone_pmd_range(struct mm_struct *dst_mm,
			       pud_t *dst_pud, pud_t *src_pud,
			       unsigned long addr, unsigned long end,
			       enum asi_clone_level level)
{
	pmd_t *src_pmd, *dst_pmd;
	unsigned long next;
	int err;

	dst_pmd = pmd_alloc(dst_mm, dst_pud, addr);
	if (!dst_pmd)
		return -ENOMEM;

	asi_set_private_pt(pud_page(*dst_pud));

	src_pmd = pmd_offset(src_pud, addr);

	do {
		next = pmd_addr_end(addr, end);
		if (level == ASI_LEVEL_PMD || pmd_none(*src_pmd) ||
		    pmd_trans_huge(*src_pmd) || pmd_devmap(*src_pmd)) {
			set_pmd(dst_pmd, *src_pmd);
			continue;
		}

		if (!pmd_present(*src_pmd)) {
			pr_warn("PMD not present for [%lx,%lx]\n",
				addr, next - 1);
			pmd_clear(dst_pmd);
			continue;
		}

		err = asi_clone_pte_range(dst_mm, dst_pmd, src_pmd,
					  addr, next);
		if (err) {
			pr_err("PMD error copying PTE addr=%lx next=%lx\n",
			       addr, next);
			return err;
		}

	} while (dst_pmd++, src_pmd++, addr = next, addr < end);

	return 0;
}

static int asi_clone_pud_range(struct mm_struct *dst_mm,
			       p4d_t *dst_p4d, p4d_t *src_p4d,
			       unsigned long addr, unsigned long end,
			       enum asi_clone_level level)
{
	pud_t *src_pud, *dst_pud;
	unsigned long next;
	int err;

	dst_pud = pud_alloc(dst_mm, dst_p4d, addr);
	if (!dst_pud)
		return -ENOMEM;

	asi_set_private_pt(p4d_page(*dst_p4d));

	src_pud = pud_offset(src_p4d, addr);

	do {
		next = pud_addr_end(addr, end);
		if (level == ASI_LEVEL_PUD || pud_none(*src_pud) ||
		    pud_trans_huge(*src_pud) || pud_devmap(*src_pud)) {
			set_pud(dst_pud, *src_pud);
			continue;
		}

		err = asi_clone_pmd_range(dst_mm, dst_pud, src_pud,
					  addr, next, level);
		if (err) {
			pr_err("PUD error copying PMD addr=%lx next=%lx\n",
			       addr, next);
			return err;
		}

	} while (dst_pud++, src_pud++, addr = next, addr < end);

	return 0;
}

static int asi_clone_p4d_range(struct mm_struct *dst_mm,
			       pgd_t *dst_pgd, pgd_t *src_pgd,
			       unsigned long addr, unsigned long end,
			       enum asi_clone_level level)
{
	p4d_t *src_p4d, *dst_p4d;
	unsigned long next;
	int err;

	dst_p4d = p4d_alloc(dst_mm, dst_pgd, addr);
	if (!dst_p4d)
		return -ENOMEM;

	asi_set_private_pt(pgd_page(*dst_pgd));

	src_p4d = p4d_offset(src_pgd, addr);

	do {
		next = p4d_addr_end(addr, end);
		if (level == ASI_LEVEL_P4D || p4d_none(*src_p4d)) {
			set_p4d(dst_p4d, *src_p4d);
			continue;
		}

		err = asi_clone_pud_range(dst_mm, dst_p4d, src_p4d,
					  addr, next, level);
		if (err) {
			pr_err("P4D error copying PUD addr=%lx next=%lx\n",
			       addr, next);
			return err;
		}

	} while (dst_p4d++, src_p4d++, addr = next, addr < end);

	return 0;
}

int asi_clone_pgd_range(struct asi_ctx *asi_ctx,
			pgd_t *src_pagetable,
			unsigned long addr, unsigned long end,
			enum asi_clone_level level)
{
	struct mm_struct *dst_mm = asi_ctx->mm;
	pgd_t *dst_pagetable = asi_ctx->pgd;
	pgd_t *src_pgd, *dst_pgd;
	unsigned long next;
	int err;

	dst_pgd = pgd_offset_pgd(dst_pagetable, addr);
	src_pgd = pgd_offset_pgd(src_pagetable, addr);

	do {
		next = pgd_addr_end(addr, end);

		if (level == ASI_LEVEL_PGD || pgd_none(*src_pgd)) {
			set_pgd(dst_pgd, *src_pgd);
			continue;
		}

		err = asi_clone_p4d_range(dst_mm, dst_pgd, src_pgd,
					  addr, next, level);
		if (err) {
			pr_err("PGD error copying P4D addr=%lx next=%lx\n",
			       addr, next);
			return err;
		}

	} while (dst_pgd++, src_pgd++, addr = next, addr < end);

	return 0;
}

int asi_map_range(struct asi_ctx *asi_ctx,
		  unsigned long virt, phys_addr_t phys, pgprot_t prot,
		  int nr_pages)
{
	struct mm_struct *mm = asi_ctx->mm;
	pgd_t *pgdp = asi_ctx->pgd;
	int i;

	for (i = 0; i < nr_pages; i++) {
		spinlock_t *ptl;
		pte_t *pte;
		pgd_t *pgd;
		p4d_t *p4d;
		pud_t *pud;
		pmd_t *pmd;

		pgd = pgd_offset_pgd(pgdp, virt);
		if (!pgd_present(*pgd))
			set_pgd(pgd, __pgd(phys | check_pgprot(prot)));

		p4d = p4d_alloc(mm, pgd, virt);
		if (!p4d)
			return -ENOMEM;
		asi_set_private_pt(pgd_page(*pgd));

		pud = pud_alloc(mm, p4d, virt);
		if (!pud)
			return -ENOMEM;
		asi_set_private_pt(p4d_page(*p4d));

		pmd = pmd_alloc(mm, pud, virt);
		if (!pmd)
			return -ENOMEM;
		asi_set_private_pt(pud_page(*pud));

		pte = pte_alloc_map_lock(mm, pmd, virt, &ptl);
		asi_set_private_pt(pmd_page(*pmd));
		set_pte(pte, __pte(phys | check_pgprot(prot)));
		pte_unmap_unlock(pte, ptl);
	}

	return 0;
}

void asi_unmap_range(struct asi_ctx *asi_ctx, unsigned long virt, int nr_pages)
{
	struct mm_struct *mm = asi_ctx->mm;
	pgd_t *pgdp = asi_ctx->pgd;
	int i;

	for (i = 0; i < nr_pages; i++) {
		spinlock_t *ptl;
		pgd_t *pgd;
		p4d_t *p4d;
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;

		pgd = pgd_offset_pgd(pgdp, virt);
		if (!pgd_present(*pgd))
			continue;

		p4d = p4d_offset(pgd, virt);
		if (!p4d)
			continue;

		pud = pud_offset(p4d, virt);
		if (!pud)
			continue;

		pmd = pmd_offset(pud, virt);
		if (!pmd)
			continue;

		pte = pte_offset_map_lock(mm, pmd, virt, &ptl);
		set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
		pte_unmap_unlock(pte, ptl);
	}
}
