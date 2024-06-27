// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/array_size.h>
#include <linux/memblock.h>
#include <linux/numa.h>
#include <linux/numa_memblks.h>
#include <linux/printk.h>
#include <linux/sort.h>

#ifndef CONFIG_NUMA_KEEP_MEMINFO

/* Stub functions: */

int memory_add_physaddr_to_nid(u64 start)
{
	pr_info_once("Unknown online node for memory at 0x%llx, assuming node 0\n",
			start);
	return 0;
}
EXPORT_SYMBOL_GPL(memory_add_physaddr_to_nid);

int phys_to_target_node(u64 start)
{
	pr_info_once("Unknown target node for memory at 0x%llx, assuming node 0\n",
			start);
	return 0;
}
EXPORT_SYMBOL_GPL(phys_to_target_node);

#endif /* !!CONFIG_NUMA_KEEP_MEMINFO */
