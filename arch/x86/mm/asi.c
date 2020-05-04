// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019, 2020, Oracle and/or its affiliates.
 *
 * Kernel Address Space Isolation (ASI)
 */

#include <linux/mm.h>
#include <linux/slab.h>

#include <asm/asi.h>
#include <asm/bug.h>

struct asi *asi_create(struct asi_type *type)
{
	struct asi *asi;

	if (!type)
		return NULL;

	asi = kzalloc(sizeof(*asi), GFP_KERNEL);
	if (!asi)
		return NULL;

	asi->type = type;

	return asi;
}
EXPORT_SYMBOL(asi_create);

void asi_destroy(struct asi *asi)
{
	kfree(asi);
}
EXPORT_SYMBOL(asi_destroy);

void asi_set_pagetable(struct asi *asi, pgd_t *pagetable)
{
	/*
	 * Check that the specified pagetable is properly aligned to be
	 * used as an ASI pagetable. If not, the pagetable is ignored
	 * and entering/exiting ASI will do nothing.
	 */
	if (!(((unsigned long)pagetable) & ASI_PGTABLE_MASK)) {
		WARN(1, "ASI %p: invalid ASI pagetable", asi);
		asi->pagetable = NULL;
		return;
	}
	asi->pagetable = pagetable;

	/*
	 * Initialize the invariant part of the ASI CR3 value. We will
	 * just have to complete the PCID with the kernel PCID before
	 * using it.
	 */
	asi->base_cr3 = __sme_pa(asi->pagetable) |
		(asi->type->pcid_prefix << ASI_PCID_PREFIX_SHIFT);

}
EXPORT_SYMBOL(asi_set_pagetable);
