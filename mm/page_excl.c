// SPDX-License-Identifier: GPL-2.0-only

#include <linux/io.h>
#include <linux/mm.h>
#include <linux/asi.h>
#include <linux/page_excl.h>

void page_unmake_exclusive(struct page *page, unsigned int order)
{
	if (order != 0)
		return;

	/* FIXME: clear alias PTE in EXCLUSIVE_ area */
	__clear_page_kernel_exclusive(page);
	set_direct_map_default_noflush(page);
}

int page_make_exclusive(struct page *page, unsigned int order)
{
	unsigned long old_va = (unsigned long)page_address(page);
	unsigned long new_va = old_va + EXCLUSIVE_OFFSET;
	unsigned long size = PAGE_SIZE << order;
	int err;

	if (order != 0)
		return -EINVAL;

	if (!current->mm)
		return -ESRCH;

	err = asi_map_page(current->mm, current->mm->pgd,
			   new_va, page_to_phys(page), PAGE_KERNEL);
	if (err)
		return err;

	err = set_direct_map_invalid_noflush(page);
        if (err)
		return err;

	flush_tlb_kernel_range(old_va, old_va + size);
	__set_page_kernel_exclusive(page);

	return 0;
}
