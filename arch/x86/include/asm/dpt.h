/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_X86_MM_DPT_H
#define ARCH_X86_MM_DPT_H

#include <linux/spinlock.h>
#include <linux/xarray.h>

#include <asm/pgtable.h>

enum page_table_level {
	PGT_LEVEL_PTE,
	PGT_LEVEL_PMD,
	PGT_LEVEL_PUD,
	PGT_LEVEL_P4D,
	PGT_LEVEL_PGD
};

/*
 * A decorated page-table (dpt) encapsulates a native page-table (e.g.
 * a PGD) and maintain additional attributes related to this page-table.
 */
struct dpt {
	spinlock_t		lock;		/* protect all attributes */
	pgd_t			*pagetable;	/* the actual page-table */
	unsigned int		alignment;	/* page-table alignment */

	/*
	 * A page-table can have direct references to another page-table,
	 * at different levels (PGD, P4D, PUD, PMD). When freeing or
	 * modifying a page-table, we should make sure that we free/modify
	 * parts effectively allocated to the actual page-table, and not
	 * parts of another page-table referenced from this page-table.
	 *
	 * To do so, the backend_pages XArray is used to keep track of pages
	 * used for this page-table.
	 */
	struct xarray		backend_pages;		/* page-table pages */
	unsigned long		backend_pages_count;	/* pages count */
};

extern struct dpt *dpt_create(unsigned int pgt_alignment);
extern void dpt_destroy(struct dpt *dpt);

#endif
