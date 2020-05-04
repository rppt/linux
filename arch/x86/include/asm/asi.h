/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_X86_MM_ASI_H
#define ARCH_X86_MM_ASI_H

#ifdef CONFIG_ADDRESS_SPACE_ISOLATION

/*
 * An Address Space Isolation (ASI) is defined with a struct asi and
 * associated with an ASI type (struct asi_type). All ASIs of the same
 * type reference the same ASI type.
 *
 * An ASI type has a unique PCID prefix (a value in the range [1, 255])
 * which is used to define the PCID used for the ASI CR3 value. The
 * first four bits of the ASI PCID come from the kernel PCID (a value
 * between 1 and 6, see TLB_NR_DYN_ASIDS). The remaining 8 bits are
 * filled with the ASI PCID prefix.
 *
 *   ASI PCID = (ASI Type PCID Prefix << 4) | Kernel PCID
 *
 * The ASI PCID is used to optimize TLB flushing when switching between
 * the kernel and ASI pagetables. The optimization is valid only when
 * a task switches between ASI of different types. If a task switches
 * between different ASIs with the same type then the ASI TLB the task
 * is switching to will always be flushed.
 */

#define ASI_PCID_PREFIX_SHIFT	4
#define ASI_PCID_PREFIX_MASK	0xff0
#define ASI_KERNEL_PCID_MASK	0x00f

/*
 * We use bit 12 of a pagetable pointer (and so of the CR3 value) as
 * a way to know if a pointer/CR3 is referencing a full kernel page
 * table or an ASI page table.
 *
 * A full kernel pagetable is always located on the first half of an
 * 8K buffer, while an ASI pagetable is always located on the second
 * half of an 8K buffer.
 */
#define ASI_PGTABLE_BIT		PAGE_SHIFT
#define ASI_PGTABLE_MASK	(1 << ASI_PGTABLE_BIT)

#ifndef __ASSEMBLY__

#include <linux/export.h>

struct asi_type {
	int			pcid_prefix;	/* PCID prefix */
};

/*
 * Macro to define and declare an ASI type.
 *
 * Declaring an ASI type will also define an inline function
 * (asi_create_<typename>()) to easily create an ASI of the
 * specified type.
 */
#define DEFINE_ASI_TYPE(name, pcid_prefix)			\
	struct asi_type asi_type_ ## name = {			\
		pcid_prefix,					\
	};							\
	EXPORT_SYMBOL(asi_type_ ## name)

#define DECLARE_ASI_TYPE(name)				\
	extern struct asi_type asi_type_ ## name;	\
	DECLARE_ASI_CREATE(name)

#define DECLARE_ASI_CREATE(name)			\
static inline struct asi *asi_create_ ## name(void)	\
{							\
	return asi_create(&asi_type_ ## name);		\
}

struct asi {
	struct asi_type		*type;		/* ASI type */
	pgd_t			*pagetable;	/* ASI pagetable */
	unsigned long		base_cr3;	/* base ASI CR3 */
};

extern struct asi *asi_create(struct asi_type *type);
extern void asi_destroy(struct asi *asi);
extern void asi_set_pagetable(struct asi *asi, pgd_t *pagetable);

#endif	/* __ASSEMBLY__ */

#endif	/* CONFIG_ADDRESS_SPACE_ISOLATION */

#endif
