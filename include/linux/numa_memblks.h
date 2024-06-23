/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NUMA_MEMBLKS_H
#define __NUMA_MEMBLKS_H

#ifdef CONFIG_NUMA_MEMBLKS
#include <linux/types.h>

#define NR_NODE_MEMBLKS		(MAX_NUMNODES*2)

struct numa_memblk {
	u64			start;
	u64			end;
	int			nid;
};

struct numa_meminfo {
	int			nr_blks;
	struct numa_memblk	blk[NR_NODE_MEMBLKS];
};

extern struct numa_meminfo numa_meminfo __initdata_or_meminfo;
extern struct numa_meminfo numa_reserved_meminfo __initdata_or_meminfo;

void __init numa_remove_memblk_from(int idx, struct numa_meminfo *mi);
int __init numa_cleanup_meminfo(struct numa_meminfo *mi);

int __init numa_add_memblk(int nodeid, u64 start, u64 end);

int __init numa_register_meminfo(struct numa_meminfo *mi);

extern int numa_distance_cnt;
int __init numa_alloc_distance(void);
void __init numa_reset_distance(void);
void __init numa_free_distance(void);

void __init alloc_node_data(int nid);

#endif /* CONFIG_NUMA_MEMBLKS */

#endif	/* __NUMA_MEMBLKS_H */
