// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/execmem.h>
#include <linux/vmalloc.h>

#ifdef CONFIG_XIP_KERNEL
/*
 * The XIP kernel text is mapped in the module area for modules and
 * some other stuff to work without any indirect relocations.
 * MODULES_VADDR is redefined here and not in asm/memory.h to avoid
 * recompiling the whole kernel when CONFIG_XIP_KERNEL is turned on/off.
 */
#undef MODULES_VADDR
#define MODULES_VADDR	(((unsigned long)_exiprom + ~PMD_MASK) & PMD_MASK)
#endif

#ifdef CONFIG_MMU
void *execmem_alloc(size_t size)
{
	gfp_t gfp_mask = GFP_KERNEL;
	void *p;

	/* Silence the initial allocation */
	if (IS_ENABLED(CONFIG_ARM_MODULE_PLTS))
		gfp_mask |= __GFP_NOWARN;

	p = __vmalloc_node_range(size, 1, MODULES_VADDR, MODULES_END,
				gfp_mask, PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
				__builtin_return_address(0));
	if (!IS_ENABLED(CONFIG_ARM_MODULE_PLTS) || p)
		return p;
	return __vmalloc_node_range(size, 1,  VMALLOC_START, VMALLOC_END,
				GFP_KERNEL, PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
				__builtin_return_address(0));
}
#endif
