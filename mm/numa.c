// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/memblock.h>
#include <linux/printk.h>
#include <linux/numa.h>

/* Allocate NODE_DATA for a node on the local memory */
void __init alloc_node_data(int nid)
{
	const size_t nd_size = roundup(sizeof(pg_data_t), PAGE_SIZE);
	u64 nd_pa;
	void *nd;
	int tnid;

	/*
	 * Allocate node data.  Try node-local memory and then any node.
	 * Never allocate in DMA zone.
	 */
	nd_pa = memblock_phys_alloc_try_nid(nd_size, SMP_CACHE_BYTES, nid);
	if (!nd_pa)
		panic("Cannot allocate %zu bytes for node %d data\n",
		      nd_size, nid);
	nd = __va(nd_pa);

	/* report and initialize */
	printk(KERN_INFO "NODE_DATA(%d) allocated [mem %#010Lx-%#010Lx]\n", nid,
	       nd_pa, nd_pa + nd_size - 1);
	tnid = early_pfn_to_nid(nd_pa >> PAGE_SHIFT);
	if (tnid != nid)
		printk(KERN_INFO "    NODE_DATA(%d) on node %d\n", nid, tnid);

	node_data[nid] = nd;
	memset(NODE_DATA(nid), 0, sizeof(pg_data_t));
}

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
