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
	__clear_page_exclusive(page);
	set_direct_map_default_noflush(page);
}

int page_make_exclusive(struct page *page, unsigned int order)
{
	unsigned long old_va = (unsigned long)page_address(page);
	unsigned long new_va = old_va + EXCLUSIVE_OFFSET;
	unsigned long size = PAGE_SIZE << order;
	struct asi_ctx asi_ctx;
	int err;

	if (order != 0)
		return -EINVAL;

	if (!current->mm)
		return -ESRCH;

	asi_ctx.mm = current->mm;
	asi_ctx.pgd = current->mm->pgd;
	err = asi_map_page(&asi_ctx, new_va, page_to_phys(page), PAGE_KERNEL);
	if (err)
		return err;

	err = set_direct_map_invalid_noflush(page);
        if (err)
		return err;

	flush_tlb_kernel_range(old_va, old_va + size);
	__set_page_exclusive(page);

	return 0;
}
