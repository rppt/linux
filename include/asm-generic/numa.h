/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_GENERIC_NUMA_H
#define __ASM_GENERIC_NUMA_H

#ifdef CONFIG_NUMA

#define NR_NODE_MEMBLKS		(MAX_NUMNODES * 2)

int __node_distance(int from, int to);
#define node_distance(a, b) __node_distance(a, b)

extern nodemask_t numa_nodes_parsed __initdata;

extern int numa_off;

/* Mappings between node number and cpus on that node. */
extern cpumask_var_t node_to_cpumask_map[MAX_NUMNODES];
void numa_clear_node(unsigned int cpu);

#ifndef cpumask_of_node
#ifdef CONFIG_DEBUG_PER_CPU_MAPS
const struct cpumask *cpumask_of_node(int node);
#else
/* Returns a pointer to the cpumask of CPUs on Node 'node'. */
static inline const struct cpumask *cpumask_of_node(int node)
{
	if (node == NUMA_NO_NODE)
		return cpu_all_mask;

	return node_to_cpumask_map[node];
}
#endif
#define cpumask_of_node cpumask_of_node
#endif

void __init arch_numa_init(void);
int __init numa_add_memblk(int nodeid, u64 start, u64 end);
void __init numa_set_distance(int from, int to, int distance);
void __init numa_free_distance(void);
void __init early_map_cpu_to_node(unsigned int cpu, int nid);
int __init early_cpu_to_node(int cpu);
void numa_store_cpu_info(unsigned int cpu);
void numa_add_cpu(unsigned int cpu);
void numa_remove_cpu(unsigned int cpu);

struct numa_memblk {
	u64			start;
	u64			end;
	int			nid;
};

struct numa_meminfo {
	int			nr_blks;
	struct numa_memblk	blk[NR_NODE_MEMBLKS];
};

void __init numa_remove_memblk_from(int idx, struct numa_meminfo *mi);
int __init numa_cleanup_meminfo(struct numa_meminfo *mi);

int __init numa_register_memblks(void);

#else	/* CONFIG_NUMA */

static inline void numa_store_cpu_info(unsigned int cpu) { }
static inline void numa_add_cpu(unsigned int cpu) { }
static inline void numa_remove_cpu(unsigned int cpu) { }
static inline void arch_numa_init(void) { }
static inline void early_map_cpu_to_node(unsigned int cpu, int nid) { }
static inline int early_cpu_to_node(int cpu) { return 0; }

#endif	/* CONFIG_NUMA */

#endif	/* __ASM_GENERIC_NUMA_H */
