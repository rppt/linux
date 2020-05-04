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
#include <asm/mmu_context.h>
#include <asm/tlbflush.h>

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

static void asi_switch_to_asi_cr3(struct asi *asi)
{
	unsigned long original_cr3, asi_cr3;
	struct asi_session *asi_session;
	u16 pcid;

	WARN_ON(!irqs_disabled());

	original_cr3 = __get_current_cr3_fast();

	/* build the ASI cr3 value */
	asi_cr3 = asi->base_cr3;
	if (boot_cpu_has(X86_FEATURE_PCID)) {
		pcid = original_cr3 & ASI_KERNEL_PCID_MASK;
		asi_cr3 |= pcid;
	}

	/* get the ASI session ready for entering ASI */
	asi_session = &get_cpu_var(cpu_asi_session);
	asi_session->asi = asi;
	asi_session->original_cr3 = original_cr3;
	asi_session->isolation_cr3 = asi_cr3;

	/* Update CR3 to immediately enter ASI */
	native_write_cr3(asi_cr3);
}

static void asi_switch_to_kernel_cr3(struct asi *asi)
{
	struct asi_session *asi_session;
	unsigned long original_cr3;

	WARN_ON(!irqs_disabled());

	original_cr3 = this_cpu_read(cpu_asi_session.original_cr3);
	if (boot_cpu_has(X86_FEATURE_PCID))
		original_cr3 |= X86_CR3_PCID_NOFLUSH;
	native_write_cr3(original_cr3);

	asi_session = &get_cpu_var(cpu_asi_session);
	asi_session->asi = NULL;
}

int asi_enter(struct asi *asi)
{
	struct asi *current_asi;
	unsigned long flags;

	/*
	 * We can re-enter isolation, but only with the same ASI (we don't
	 * support nesting isolation).
	 */
	current_asi = this_cpu_read(cpu_asi_session.asi);
	if (current_asi) {
		if (current_asi != asi) {
			WARN_ON(1);
			return -EBUSY;
		}
		return 0;
	}

	local_irq_save(flags);
	asi_switch_to_asi_cr3(asi);
	local_irq_restore(flags);

	return 0;
}
EXPORT_SYMBOL(asi_enter);

void asi_exit(struct asi *asi)
{
	struct asi *current_asi;
	unsigned long flags;

	current_asi = this_cpu_read(cpu_asi_session.asi);
	if (!current_asi) {
		/* already exited */
		return;
	}

	WARN_ON(current_asi != asi);

	local_irq_save(flags);
	asi_switch_to_kernel_cr3(asi);
	local_irq_restore(flags);
}
EXPORT_SYMBOL(asi_exit);
