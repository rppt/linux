// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/execmem.h>
#include <linux/vmalloc.h>

#ifdef MODULE_START
void *execmem_alloc(unsigned long size)
{
	return __vmalloc_node_range(size, 1, MODULE_START, MODULE_END,
				GFP_KERNEL, PAGE_KERNEL, 0, NUMA_NO_NODE,
				__builtin_return_address(0));
}
#endif
