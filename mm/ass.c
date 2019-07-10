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

#include <asm/pgalloc.h>

/*
 * Walk the shadow copy of the page tables to PMD level (optionally)
 * trying to allocate page table pages on the way down.
 *
 * Allocation failures are not handled here because the entire page
 * table will be freed in ass_free_pagetable.
 *
 * Returns a pointer to a PMD on success, or NULL on failure.
 */
static pmd_t *ass_pagetable_walk_pmd(struct mm_struct *mm,
				     pgd_t *pgd, unsigned long address)
{
	p4d_t *p4d;
	pud_t *pud;

	p4d = p4d_alloc(mm, pgd, address);
	if (!p4d)
		return NULL;

	pud = pud_alloc(mm, p4d, address);
	if (!pud)
		return NULL;

	return pmd_alloc(mm, pud, address);
}

/*
 * Walk the shadow copy of the page tables to PTE level (optionally)
 * trying to allocate page table pages on the way down.
 *
 * Returns a pointer to a PTE on success, or NULL on failure.
 */
static pte_t *ass_pagetable_walk_pte(struct mm_struct *mm,
				     pgd_t *pgd, unsigned long address)
{
	pmd_t *pmd = ass_pagetable_walk_pmd(mm, pgd, address);

	if (!pmd)
		return NULL;

	if (__pte_alloc(mm, pmd))
		return NULL;

	return pte_offset_kernel(pmd, address);
}

/*
 * Clone a single page mapping
 *
 * The new mapping in the @target_pgdp is always created for base
 * page. If the orinal page table has the page at @addr mapped at PMD
 * level, we anyway create at PTE in the target page table and map
 * only PAGE_SIZE.
 */
pte_t *ass_clone_page(struct mm_struct *mm,
		      pgd_t *pgdp, pgd_t *target_pgdp,
		      unsigned long addr)
{
	pte_t *pte, *target_pte, ptev;
	pgd_t *pgd, *target_pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset_pgd(pgdp, addr);
	if (pgd_none(*pgd))
		return NULL;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d))
		return NULL;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return NULL;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;

	target_pgd = pgd_offset_pgd(target_pgdp, addr);

	if (pmd_large(*pmd)) {
		pgprot_t flags;
		unsigned long pfn;

		/*
		 * We map only PAGE_SIZE rather than the entire huge page.
		 * The PTE will have the same pgprot bits as the origial PMD
		 */
		flags = pte_pgprot(pte_clrhuge(*(pte_t *)pmd));
		pfn = pmd_pfn(*pmd) + pte_index(addr);
		ptev = pfn_pte(pfn, flags);
	} else {
		pte = pte_offset_kernel(pmd, addr);
		if (pte_none(*pte) || !(pte_flags(*pte) & _PAGE_PRESENT))
			return NULL;

		ptev = *pte;
	}

	target_pte = ass_pagetable_walk_pte(mm, target_pgd, addr);
	if (!target_pte)
		return NULL;

	*target_pte = ptev;

	return target_pte;
}

/*
 * Clone a range keeping the same leaf mappings
 *
 * If the range has holes they are simply skipped
 */
int ass_clone_range(struct mm_struct *mm,
		    pgd_t *pgdp, pgd_t *target_pgdp,
		    unsigned long start, unsigned long end)
{
	unsigned long addr;

	/*
	 * Clone the populated PMDs which cover start to end. These PMD areas
	 * can have holes.
	 */
	for (addr = start; addr < end;) {
		pte_t *pte, *target_pte;
		pgd_t *pgd, *target_pgd;
		pmd_t *pmd, *target_pmd;
		p4d_t *p4d;
		pud_t *pud;

		/* Overflow check */
		if (addr < start)
			break;

		pgd = pgd_offset_pgd(pgdp, addr);
		if (pgd_none(*pgd))
			return 0;

		p4d = p4d_offset(pgd, addr);
		if (p4d_none(*p4d))
			return 0;

		pud = pud_offset(p4d, addr);
		if (pud_none(*pud)) {
			addr += PUD_SIZE;
			continue;
		}

		pmd = pmd_offset(pud, addr);
		if (pmd_none(*pmd)) {
			addr += PMD_SIZE;
			continue;
		}

		target_pgd = pgd_offset_pgd(target_pgdp, addr);

		if (pmd_large(*pmd)) {
			target_pmd = ass_pagetable_walk_pmd(mm, target_pgd,
							    addr);
			if (!target_pmd)
				return -ENOMEM;

			*target_pmd = *pmd;

			addr += PMD_SIZE;
			continue;
		} else {
			pte = pte_offset_kernel(pmd, addr);
			if (pte_none(*pte)) {
				addr += PAGE_SIZE;
				continue;
			}

			target_pte = ass_pagetable_walk_pte(mm, target_pgd,
							    addr);
			if (!target_pte)
				return -ENOMEM;

			*target_pte = *pte;

			addr += PAGE_SIZE;
		}
	}

	return 0;
}

static int ass_free_pte_range(struct mm_struct *mm, pmd_t *pmd)
{
	pte_t *ptep = pte_offset_kernel(pmd, 0);

	pmd_clear(pmd);
	pte_free(mm, virt_to_page(ptep));
	mm_dec_nr_ptes(mm);

	return 0;
}

static int ass_free_pmd_range(struct mm_struct *mm, pud_t *pud)
{
	pmd_t *pmd, *pmdp;
	int i;

	pmdp = pmd_offset(pud, 0);

	for (i = 0, pmd = pmdp; i < PTRS_PER_PMD; i++, pmd++)
		if (!pmd_none(*pmd) && !pmd_large(*pmd))
			ass_free_pte_range(mm, pmd);

	pud_clear(pud);
	pmd_free(mm, pmdp);
	mm_dec_nr_pmds(mm);

	return 0;
}

static int ass_free_pud_range(struct mm_struct *mm, p4d_t *p4d)
{
	pud_t *pud, *pudp;
	int i;

	pudp = pud_offset(p4d, 0);

	for (i = 0, pud = pudp; i < PTRS_PER_PUD; i++, pud++)
		if (!pud_none(*pud))
			ass_free_pmd_range(mm, pud);

	p4d_clear(p4d);
	pud_free(mm, pudp);
	mm_dec_nr_puds(mm);

	return 0;
}

static int ass_free_p4d_range(struct mm_struct *mm, pgd_t *pgd)
{
	p4d_t *p4d, *p4dp;
	int i;

	p4dp = p4d_offset(pgd, 0);

	for (i = 0, p4d = p4dp; i < PTRS_PER_P4D; i++, p4d++)
		if (!p4d_none(*p4d))
			ass_free_pud_range(mm, p4d);

	pgd_clear(pgd);
	p4d_free(mm, p4dp);

	return 0;
}

int ass_free_pagetable(struct task_struct *tsk, pgd_t *ass_pgd)
{
	struct mm_struct *mm = tsk->mm;
	pgd_t *pgd, *pgdp = ass_pgd;

	for (pgd = pgdp + KERNEL_PGD_BOUNDARY; pgd < pgdp + PTRS_PER_PGD; pgd++)
		if (!pgd_none(*pgd))
			ass_free_p4d_range(mm, pgd);


	return 0;
}
