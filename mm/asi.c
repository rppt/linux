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

#include <asm/pgalloc.h>

#undef pr_fmt
#define pr_fmt(fmt)     "ASI: " fmt

static int asi_clone_pte_range(struct mm_struct *dst_mm,
			       struct mm_struct *src_mm,
			       pmd_t *dst_pmd, pmd_t *src_pmd,
			       unsigned long addr, unsigned long end)
{
	pte_t *src_pte, *dst_pte;

	dst_pte = pte_alloc_map(dst_mm, dst_pmd, addr);
	if (!dst_pte)
		return -ENOMEM;

	addr &= PAGE_MASK;
	src_pte = pte_offset_map(src_pmd, addr);

	do {
		set_pte(dst_pte, *src_pte);
	} while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr < end);

	return 0;
}

static int asi_clone_pmd_range(struct mm_struct *dst_mm,
			       struct mm_struct *src_mm,
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

		err = asi_clone_pte_range(dst_mm, src_mm, dst_pmd, src_pmd,
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
			       struct mm_struct *src_mm,
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

	src_pud = pud_offset(src_p4d, addr);

	do {
		next = pud_addr_end(addr, end);
		if (level == ASI_LEVEL_PUD || pud_none(*src_pud) ||
		    pud_trans_huge(*src_pud) || pud_devmap(*src_pud)) {
			set_pud(dst_pud, *src_pud);
			continue;
		}

		err = asi_clone_pmd_range(dst_mm, src_mm, dst_pud, src_pud,
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
			       struct mm_struct *src_mm,
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

	src_p4d = p4d_offset(src_pgd, addr);

	do {
		next = p4d_addr_end(addr, end);
		if (level == ASI_LEVEL_P4D || p4d_none(*src_p4d)) {
			set_p4d(dst_p4d, *src_p4d);
			continue;
		}

		err = asi_clone_pud_range(dst_mm, src_mm, dst_p4d, src_p4d,
					  addr, next, level);
		if (err) {
			pr_err("P4D error copying PUD addr=%lx next=%lx\n",
			       addr, next);
			return err;
		}

	} while (dst_p4d++, src_p4d++, addr = next, addr < end);

	return 0;
}

int asi_clone_pgd_range(struct mm_struct *dst_mm,
			struct mm_struct *src_mm,
			pgd_t *dst_pagetable, pgd_t *src_pagetable,
			unsigned long addr, unsigned long end,
			enum asi_clone_level level)
{
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

		err = asi_clone_p4d_range(dst_mm, src_mm, dst_pgd, src_pgd,
					  addr, next, level);
		if (err) {
			pr_err("PGD error copying P4D addr=%lx next=%lx\n",
			       addr, next);
			return err;
		}

	} while (dst_pgd++, src_pgd++, addr = next, addr < end);

	return 0;
}

int asi_map_range(struct mm_struct *mm, pgd_t *pgdp,
		  unsigned long virt, phys_addr_t phys, pgprot_t prot,
		  int nr_pages)
{
	int i;

	for (i = 0; i < nr_pages; i++) {
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

		pud = pud_alloc(mm, p4d, virt);
		if (!pud)
			return -ENOMEM;

		pmd = pmd_alloc(mm, pud, virt);
		if (!pmd)
			return -ENOMEM;

		pte = pte_alloc_map(mm, pmd, virt);
		set_pte(pte, __pte(phys | check_pgprot(prot)));
	}

	return 0;
}
