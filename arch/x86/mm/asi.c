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
	asi->pgtable_id = atomic64_inc_return(&type->last_pgtable_id);
	atomic64_set(&asi->pgtable_gen, 0);

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

/*
 * Update ASI TLB flush information for the specified ASI CR3 value.
 * Return an updated ASI CR3 value which specified if TLB needs to
 * be flushed or not.
 */
unsigned long asi_update_flush(struct asi *asi, unsigned long asi_cr3)
{
	struct asi_tlb_pgtable *tlb_pgtable;
	struct asi_tlb_state *tlb_state;
	s64 pgtable_gen;
	u16 pcid;

	pcid = asi_cr3 & ASI_KERNEL_PCID_MASK;
	tlb_state = get_cpu_ptr(asi->type->tlb_state);
	tlb_pgtable = &tlb_state->tlb_pgtables[pcid - 1];
	pgtable_gen = atomic64_read(&asi->pgtable_gen);
	if (tlb_pgtable->id == asi->pgtable_id &&
	    tlb_pgtable->gen == pgtable_gen) {
		asi_cr3 |= X86_CR3_PCID_NOFLUSH;
	} else {
		tlb_pgtable->id = asi->pgtable_id;
		tlb_pgtable->gen = pgtable_gen;
	}

	return asi_cr3;
}


/*
 * Switch to the ASI pagetable.
 *
 * If schedule is ASI_SWITCH_NOW, then immediately switch to the ASI
 * pagetable by updating the CR3 register with the ASI CR3 value.
 * Otherwise, if schedule is ASI_SWITCH_ON_RESUME, prepare everything
 * for switching to ASI pagetable but do not update the CR3 register
 * yet. This will be done by the next ASI_RESUME call.
 */

enum asi_switch_schedule {
	ASI_SWITCH_NOW,
	ASI_SWITCH_ON_RESUME,
};

static void asi_switch_to_asi_cr3(struct asi *asi,
				  enum asi_switch_schedule schedule)
{
	unsigned long original_cr3, asi_cr3;
	struct asi_session *asi_session;
	u16 pcid;

	WARN_ON(!irqs_disabled());

	original_cr3 = __get_current_cr3_fast();

	/* build the ASI cr3 value */
	if (boot_cpu_has(X86_FEATURE_PCID)) {
		pcid = original_cr3 & ASI_KERNEL_PCID_MASK;
		asi_cr3 = asi_update_flush(asi, asi->base_cr3 | pcid);
	} else {
		asi_cr3 = asi->base_cr3;
	}

	/* get the ASI session ready for entering ASI */
	asi_session = &get_cpu_var(cpu_asi_session);
	asi_session->asi = asi;
	asi_session->original_cr3 = original_cr3;
	asi_session->isolation_cr3 = asi_cr3;

	if (schedule == ASI_SWITCH_ON_RESUME) {
		/*
		 * Defer the CR3 update the next ASI resume by setting
		 * the interrupt depth to 1.
		 */
		asi_session->idepth = 1;
	} else {
		/* Update CR3 to immediately enter ASI */
		native_write_cr3(asi_cr3);
	}
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
	asi_session->idepth = 0;
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
	asi_switch_to_asi_cr3(asi, ASI_SWITCH_NOW);
	local_irq_restore(flags);

	return 0;
}
EXPORT_SYMBOL(asi_enter);

void asi_exit(struct asi *asi)
{
	struct asi_session *asi_session;
	struct asi *current_asi;
	unsigned long flags;
	int idepth;

	current_asi = this_cpu_read(cpu_asi_session.asi);
	if (!current_asi) {
		/* already exited */
		return;
	}

	WARN_ON(current_asi != asi);

	idepth = this_cpu_read(cpu_asi_session.idepth);
	if (!idepth) {
		local_irq_save(flags);
		asi_switch_to_kernel_cr3(asi);
		local_irq_restore(flags);
	} else {
		/*
		 * ASI was interrupted so we already switched back
		 * to the back to the kernel page table and we just
		 * need to clear the ASI session.
		 */
		asi_session = &get_cpu_var(cpu_asi_session);
		asi_session->asi = NULL;
		asi_session->idepth = 0;
	}
}
EXPORT_SYMBOL(asi_exit);

void asi_prepare_resume(void)
{
	struct asi_session *asi_session;

	asi_session = &get_cpu_var(cpu_asi_session);
	if (!asi_session->asi || asi_session->idepth > 1)
		return;

	asi_switch_to_asi_cr3(asi_session->asi, ASI_SWITCH_ON_RESUME);
}

void asi_schedule_out(struct task_struct *task)
{
	struct asi_session *asi_session;
	unsigned long flags;
	struct asi *asi;

	asi = this_cpu_read(cpu_asi_session.asi);
	if (!asi)
		return;

	/*
	 * Save the ASI session.
	 *
	 * Exit the session if it hasn't been interrupted, otherwise
	 * just save the session state.
	 */
	local_irq_save(flags);
	if (!this_cpu_read(cpu_asi_session.idepth)) {
		asi_switch_to_kernel_cr3(asi);
		task->asi_session.asi = asi;
		task->asi_session.idepth = 0;
	} else {
		asi_session = &get_cpu_var(cpu_asi_session);
		task->asi_session = *asi_session;
		asi_session->asi = NULL;
		asi_session->idepth = 0;
	}
	local_irq_restore(flags);
}

void asi_schedule_in(struct task_struct *task)
{
	struct asi_session *asi_session;
	unsigned long flags;
	struct asi *asi;

	asi = task->asi_session.asi;
	if (!asi)
		return;

	/*
	 * At this point, the CPU shouldn't be using ASI because the
	 * ASI session is expected to be cleared in asi_schedule_out().
	 */
	WARN_ON(this_cpu_read(cpu_asi_session.asi));

	/*
	 * Restore ASI.
	 *
	 * If the task was scheduled out while using ASI, then the ASI
	 * is already setup and we can immediately switch to ASI page
	 * table.
	 *
	 * Otherwise, if the task was scheduled out while ASI was
	 * interrupted, just restore the ASI session.
	 */
	local_irq_save(flags);
	if (!task->asi_session.idepth) {
		asi_switch_to_asi_cr3(asi, ASI_SWITCH_NOW);
	} else {
		asi_session = &get_cpu_var(cpu_asi_session);
		*asi_session = task->asi_session;
	}
	task->asi_session.asi = NULL;
	local_irq_restore(flags);
}
