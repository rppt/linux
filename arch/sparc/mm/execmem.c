// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/execmem.h>
#include <linux/vmalloc.h>

#ifdef CONFIG_SPARC64
void *execmem_alloc(size_t size)
{
	if (PAGE_ALIGN(size) > MODULES_LEN)
		return NULL;
	return __vmalloc_node_range(size, 1, MODULES_VADDR, MODULES_END,
				GFP_KERNEL, PAGE_KERNEL, 0, NUMA_NO_NODE,
				__builtin_return_address(0));
}
#else
void *execmem_alloc(size_t size)
{
	return vmalloc(size);
}
#endif /* CONFIG_SPARC64 */
