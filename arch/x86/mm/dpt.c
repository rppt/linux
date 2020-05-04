// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019, 2020, Oracle and/or its affiliates.
 *
 */

#include <linux/slab.h>

#include <asm/dpt.h>

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

	return dpt;
}
EXPORT_SYMBOL(dpt_create);

void dpt_destroy(struct dpt *dpt)
{
	unsigned int pgt_alignment;
	unsigned int alloc_order;

	if (!dpt)
		return;

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
