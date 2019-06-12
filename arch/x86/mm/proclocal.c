/*
 * Architecture-specific code for handling process-local memory on x86-64.
 *
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */

#include <linux/list.h>
#include <linux/mm.h>
#include <linux/proclocal.h>
#include <linux/set_memory.h>
#include <asm/tlb.h>

extern void handle_proclocal_page(struct mm_struct *mm, struct page *page,
				  unsigned long addr);

static void unmap_leftover_pages_pte(struct mm_struct *mm, pmd_t *pmd,
				     unsigned long addr, unsigned long end,
				     struct list_head *page_list)
{
	pte_t *pte;
	struct page *page;

	for (pte = pte_offset_map(pmd, addr);
	     addr < end; addr += PAGE_SIZE, pte++) {
		if (!pte_present(*pte))
			continue;

		page = pte_page(*pte);
		pte_clear(mm, addr, pte);
		set_direct_map_default_noflush(page);

		/* callback to non-arch allocator */
		handle_proclocal_page(mm, page, addr);
		/*
		 * scrub page contents. since mm teardown happens from a
		 * different mm, we cannot just use the process-local virtual
		 * address; access the page via the physmap instead. note that
		 * there is a small time frame where leftover data is globally
		 * visible in the kernel address space.
		 *
		 * tbd in later commit: scrub the page via a temporary mapping
		 * in process-local memory area before re-attaching it to the
		 * physmap.
		 */
		memset(page_to_virt(page), 0, PAGE_SIZE);

		/*
		 * track page for cleanup later;
		 * note that the proclocal_next list is used only for regular
		 * kfree_proclocal, so ripping pages out now is fine.
		 */
		INIT_LIST_HEAD(&page->proclocal_next);
		list_add_tail(&page->proclocal_next, page_list);
	}
}

/*
 * Walk through process-local mappings on each page table level. Avoid code
 * duplication and use a macro to generate one function for each level.
 *
 * The macro generates a function for page table level LEVEL. The function is
 * passed a pointer to the entry in the page table level ABOVE and recurses into
 * the page table level BELOW.
 */
#define UNMAP_LEFTOVER_LEVEL(LEVEL, ABOVE, BELOW) \
	static void unmap_leftover_pages_ ## LEVEL (struct mm_struct *mm, ABOVE ## _t *ABOVE,	\
						    unsigned long addr, unsigned long end,	\
						    struct list_head *page_list)		\
	{										\
		LEVEL ## _t *LEVEL  = LEVEL ## _offset(ABOVE, addr);			\
		unsigned long next;							\
		do {									\
			next = LEVEL ## _addr_end(addr, end);				\
			if (LEVEL ## _present(*LEVEL))					\
				unmap_leftover_pages_## BELOW (mm, LEVEL, addr, next, page_list); \
		} while (LEVEL++, addr = next, addr < end);				\
	}

UNMAP_LEFTOVER_LEVEL(pmd, pud, pte)
UNMAP_LEFTOVER_LEVEL(pud, p4d, pmd)
UNMAP_LEFTOVER_LEVEL(p4d, pgd, pud)
#undef UNMAP_LEFTOVER_LEVEL

extern void proclocal_release_pages(struct list_head *pages);

static void unmap_free_leftover_proclocal_pages(struct mm_struct *mm)
{
	LIST_HEAD(page_list);
	unsigned long addr = PROCLOCAL_START, next;
	unsigned long end = PROCLOCAL_START + PROCLOCAL_SIZE;

	/*
	 * Walk page tables in process-local memory area and handle leftover
	 * process-local pages. Note that we cannot use the kernel's
	 * walk_page_range, because that function assumes walking across vmas.
	 */
	spin_lock(&mm->page_table_lock);
	do {
		pgd_t *pgd = pgd_offset(mm, addr);
		next = pgd_addr_end(addr, end);

		if (pgd_present(*pgd)) {
			unmap_leftover_pages_p4d(mm, pgd, addr, next, &page_list);
		}
		addr = next;
	} while (addr < end);
	spin_unlock(&mm->page_table_lock);
	/*
	 * Flush any mappings of process-local pages from the TLBs, so that we
	 * can release the pages afterwards.
	 */
	flush_tlb_mm_range(mm, PROCLOCAL_START, end, PAGE_SHIFT, false);
	proclocal_release_pages(&page_list);
}

static void arch_proclocal_teardown_pt(struct mm_struct *mm)
{
	struct mmu_gather tlb;
	/*
	 * clean up page tables for the whole pgd used exclusively by
	 * process-local memory.
	 */
	unsigned long proclocal_base_pgd = PROCLOCAL_START & PGDIR_MASK;
	unsigned long proclocal_end_pgd = proclocal_base_pgd + PGDIR_SIZE;

	tlb_gather_mmu(&tlb, mm, proclocal_base_pgd, proclocal_end_pgd);
	free_pgd_range(&tlb, proclocal_base_pgd, proclocal_end_pgd, 0, 0);
	tlb_finish_mmu(&tlb, proclocal_base_pgd, proclocal_end_pgd);
}

void arch_proclocal_teardown_pages_and_pt(struct mm_struct *mm)
{
	if (mm->proclocal_nr_pages)
		unmap_free_leftover_proclocal_pages(mm);
	arch_proclocal_teardown_pt(mm);
}
