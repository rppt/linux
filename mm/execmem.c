// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/execmem.h>
#include <linux/moduleloader.h>
#include <linux/set_memory.h>

#include <asm/text-patching.h>

void __weak *execmem_alloc(size_t size)
{
	return __vmalloc_node_range(size, PAGE_SIZE, VMALLOC_START, VMALLOC_END,
			GFP_KERNEL, PAGE_KERNEL_EXEC, VM_FLUSH_RESET_PERMS,
			NUMA_NO_NODE, __builtin_return_address(0));
}

void execmem_free(void *ptr)
{
	/*
	 * This memory may be RO, and freeing RO memory in an interrupt is not
	 * supported by vmalloc.
	 */
	WARN_ON(in_interrupt());
	vfree(ptr);
}

void execmem_update_copy(void *dst, void *src, size_t size)
{
	text_poke_copy(dst, src, size);
}
