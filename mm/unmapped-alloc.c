// SPDX-License-Identifier: GPL-2.0

#include <linux/gfp.h>
#include <linux/mmzone.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/set_memory.h>

#include <asm/tlbflush.h>

#include "internal.h"

struct unmapped_free_area {
	struct list_head	free_list;
	spinlock_t		lock;
	unsigned long		nr_free;
	unsigned long		nr_cached;
};

static struct unmapped_free_area free_area[MAX_ORDER];

static inline void add_to_free_list(struct page *page, unsigned int order)
{
	struct unmapped_free_area *area = &free_area[order];

	list_add(&page->buddy_list, &area->free_list);
	area->nr_free++;
}

static inline void del_page_from_free_list(struct page *page, unsigned int order)
{
	list_del(&page->buddy_list);
	__ClearPageUnmapped(page);
	set_page_private(page, 0);
	free_area[order].nr_free--;
}

static inline void set_unmapped_order(struct page *page, unsigned int order)
{
	set_page_private(page, order);
	__SetPageUnmapped(page);
}

static inline bool page_is_unmapped_buddy(struct page *page, struct page *buddy,
					  unsigned int order)
{
	if (!PageUnmapped(buddy))
		return false;

	if (buddy_order(buddy) != order)
		return false;

	return true;
}

static struct page *find_unmapped_buddy_page_pfn(struct page *page,
						 unsigned long pfn,
						 unsigned int order,
						 unsigned long *buddy_pfn)
{
	unsigned long __buddy_pfn = __find_buddy_pfn(pfn, order);
	struct page *buddy;

	buddy = page + (__buddy_pfn - pfn);
	if (buddy_pfn)
		*buddy_pfn = __buddy_pfn;

	if (page_is_unmapped_buddy(page, buddy, order))
		return buddy;

	return NULL;
}

static inline void __free_one_page(struct page *page, unsigned int order,
				   bool cache_refill)
{
	unsigned long pfn = page_to_pfn(page);
	unsigned long buddy_pfn;
	unsigned long combined_pfn;
	struct page *buddy;
	unsigned long flags;

	spin_lock_irqsave(&free_area->lock, flags);

	if (cache_refill)
		free_area[order].nr_cached++;

	while (order < MAX_ORDER - 1) {
		buddy = find_unmapped_buddy_page_pfn(page, pfn, order,
						     &buddy_pfn);
		if (!buddy)
			break;

		del_page_from_free_list(buddy, order);
		combined_pfn = buddy_pfn & pfn;
		page = page + (combined_pfn - pfn);
		pfn = combined_pfn;
		order++;
	}

	set_unmapped_order(page, order);
	add_to_free_list(page, order);
	spin_unlock_irqrestore(&free_area->lock, flags);

	if (cache_refill)
		dump_page(page, "unmapped");
}

static inline void expand(struct page *page, int low, int high)
{
	unsigned long size = 1 << high;

	while (high > low) {
		high--;
		size >>= 1;

		add_to_free_list(&page[size], high);
		set_unmapped_order(&page[size], high);
	}
}

static struct page *__rmqueue_smallest(unsigned int order)
{
	unsigned int current_order;
	struct unmapped_free_area *area;
	struct page *page = NULL;
	unsigned long flags;

	spin_lock_irqsave(&free_area->lock, flags);

	/* Find a page of the appropriate size in the preferred list */
	for (current_order = order; current_order < MAX_ORDER; ++current_order) {
		area = &free_area[current_order];
		page = list_first_entry_or_null(&area->free_list, struct page,
						lru);
		if (!page)
			continue;

		del_page_from_free_list(page, current_order);
		expand(page, order, current_order);

		break;
	}

	spin_unlock_irqrestore(&free_area->lock, flags);

	return page;
}

/* FIXME: have PMD_ORDER at last available in include/linux */
#define PMD_ORDER	(PMD_SHIFT - PAGE_SHIFT)

struct page *unmapped_pages_alloc(gfp_t gfp, int order)
{

	int cache_order = PMD_ORDER;
	struct page *page;

	page = __rmqueue_smallest(order);
	if (page)
		return page;

	while (cache_order >= order) {
		page = alloc_pages(gfp | __GFP_ZERO, cache_order);
		if (page)
			break;
		cache_order--;
	}

	if (page) {
		unsigned long addr = (unsigned long)page_address(page);
		unsigned long nr_pages = (1 << order);
		unsigned long size = PAGE_SIZE * nr_pages;

		split_page(page, order);
		pr_info("===> unmap: addr: %lx nr: %ld\n", addr, nr_pages);
		set_memory_np(addr, nr_pages);
		flush_tlb_kernel_range(addr, addr + size);

		/*
		 * FIXME: have this under lock so that allocation running
		 * in parallel won't steal all pages from the newly cached
		 * ones
		 */
		__free_one_page(page, cache_order, true);
		page = __rmqueue_smallest(order);
	}

	return page;
}

void unmapped_pages_free(struct page *page, int order)
{
	__free_one_page(page, order, false);
}

int unmapped_alloc_init(void)
{
	for (int order = 0; order < MAX_ORDER; order++) {
		struct unmapped_free_area *area = &free_area[order];
		INIT_LIST_HEAD(&area->free_list);
		spin_lock_init(&area->lock);
	}

	return 0;
}
