/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_X86_MM_DPT_H
#define ARCH_X86_MM_DPT_H

#include <linux/spinlock.h>

#include <asm/pgtable.h>

/*
 * A decorated page-table (dpt) encapsulates a native page-table (e.g.
 * a PGD) and maintain additional attributes related to this page-table.
 */
struct dpt {
	spinlock_t		lock;		/* protect all attributes */
	pgd_t			*pagetable;	/* the actual page-table */
	unsigned int		alignment;	/* page-table alignment */

};

extern struct dpt *dpt_create(unsigned int pgt_alignment);
extern void dpt_destroy(struct dpt *dpt);

#endif
