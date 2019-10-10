// SPDX-License-Identifier: GPL-2.0-only

#include <linux/io.h>
#include <linux/mm.h>
#include <linux/asi.h>
#include <linux/page_excl.h>

void page_unmake_exclusive(struct page *page, unsigned int order)
{
	unsigned long addr = (unsigned long)page_address(page);
	unsigned long size = PAGE_SIZE * (1 << order);
	struct asi_ctx *asi_ctx = page->asi_ctx;

	/*
	 * The order is important because page_address() of an exclusive
	 * page i s in a separate virtual range. ASI APIs use this range
	 * and set_direct_map use the standard range in the direct mapping
	 */
	asi_unmap_range(asi_ctx, addr, addr + size);
	__ClearPageExclusive(page);
	set_direct_map_default_noflush(page, (1 << order));
}

int page_make_exclusive(struct page *page, unsigned int order)
{
	unsigned long old_va = (unsigned long)page_address(page);
	unsigned long new_va = old_va + EXCLUSIVE_OFFSET;
	unsigned long size = PAGE_SIZE * (1 << order);
	struct asi_ctx *asi_ctx;
	int err;

	if (order != 0)
		return -EINVAL;

	if (!current->mm)
		return -ESRCH;

	asi_ctx = current->mm->asi_ctx;
	err = asi_map_page(asi_ctx, new_va, page_to_phys(page), PAGE_KERNEL);
	if (err)
		return err;

	err = set_direct_map_invalid_noflush(page, (1 << order));
        if (err) {
		asi_unmap_range(asi_ctx, new_va, size);
		return err;
	}

	page->asi_ctx = asi_ctx;
	flush_tlb_kernel_range(old_va, old_va + size);
	__SetPageExclusive(page);

	return 0;
}
