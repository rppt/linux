// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/execmem.h>
#include <linux/vmalloc.h>

void *execmem_alloc(size_t size)
{
	/* using RWX means less protection for modules, but it's
	 * easier than trying to map the text, data, init_text and
	 * init_data correctly */
	return __vmalloc_node_range(size, 1, VMALLOC_START, VMALLOC_END,
				    GFP_KERNEL,
				    PAGE_KERNEL_RWX, 0, NUMA_NO_NODE,
				    __builtin_return_address(0));
}
