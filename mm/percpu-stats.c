/*
 * mm/percpu-debug.c
 *
 * Copyright (C) 2017		Facebook Inc.
 * Copyright (C) 2017		Dennis Zhou <dennisz@fb.com>
 *
 * This file is released under the GPLv2.
 *
 * Prints statistics about the percpu allocator and backing chunks.
 */
#include <linux/debugfs.h>
#include <linux/list.h>
#include <linux/percpu.h>
#include <linux/seq_file.h>
#include <linux/sort.h>
#include <linux/vmalloc.h>

#include "percpu-internal.h"

#define P(X, Y) \
	seq_printf(m, "  %-20s: %12lld\n", X, (long long int)Y)

struct percpu_stats pcpu_stats;
struct pcpu_alloc_info pcpu_stats_ai;

static int cmpint(const void *a, const void *b)
{
	return *(int *)a - *(int *)b;
}

/*
 * Iterates over all chunks to find the max nr_alloc entries.
 */
static int find_max_nr_alloc(void)
{
	struct pcpu_chunk *chunk;
	int slot, max_nr_alloc;

	max_nr_alloc = 0;
	for (slot = 0; slot < pcpu_nr_slots; slot++)
		list_for_each_entry(chunk, &pcpu_slot[slot], list)
			max_nr_alloc = max(max_nr_alloc, chunk->nr_alloc);

	return max_nr_alloc;
}

static void get_chunk_alloc_info(struct pcpu_chunk *chunk,
				 struct pcpu_allocs_info *allocs)
{
	int region_bits = pcpu_chunk_map_bits(chunk);
	int i, j;

	for (i = 0; i < region_bits; i++) {
		struct pcpu_allocs_info *ai = &chunk->allocs[i];

		if (!ai->size)
			continue;

		for (j = 0; allocs[j].size; j++) {
			if (allocs[j].size == ai->size &&
			    allocs[j].caller == ai->caller) {
				allocs[j].count++;
				break;
			}
		}

		if (!allocs[j].size) {
			allocs[j].size = ai->size;
			allocs[j].caller = ai->caller;
			allocs[j].count = 1;
		}
	}
}

/*
 * Prints out chunk state. Fragmentation is considered between
 * the beginning of the chunk to the last allocation.
 *
 * All statistics are in bytes unless stated otherwise.
 */
static void chunk_map_stats(struct seq_file *m, struct pcpu_chunk *chunk,
			    int *buffer)
{
	int i, last_alloc, as_len, start, end;
	int *alloc_sizes, *p;
	/* statistics */
	int sum_frag = 0, max_frag = 0;
	int cur_min_alloc = 0, cur_med_alloc = 0, cur_max_alloc = 0;

	alloc_sizes = buffer;

	/*
	 * find_last_bit returns the start value if nothing found.
	 * Therefore, we must determine if it is a failure of find_last_bit
	 * and set the appropriate value.
	 */
	last_alloc = find_last_bit(chunk->alloc_map,
				   pcpu_chunk_map_bits(chunk) -
				   chunk->end_offset / PCPU_MIN_ALLOC_SIZE - 1);
	last_alloc = test_bit(last_alloc, chunk->alloc_map) ?
		     last_alloc + 1 : 0;

	as_len = 0;
	start = chunk->start_offset / PCPU_MIN_ALLOC_SIZE;

	/*
	 * If a bit is set in the allocation map, the bound_map identifies
	 * where the allocation ends.  If the allocation is not set, the
	 * bound_map does not identify free areas as it is only kept accurate
	 * on allocation, not free.
	 *
	 * Positive values are allocations and negative values are free
	 * fragments.
	 */
	while (start < last_alloc) {
		if (test_bit(start, chunk->alloc_map)) {
			end = find_next_bit(chunk->bound_map, last_alloc,
					    start + 1);
			alloc_sizes[as_len] = 1;
		} else {
			end = find_next_bit(chunk->alloc_map, last_alloc,
					    start + 1);
			alloc_sizes[as_len] = -1;
		}

		alloc_sizes[as_len++] *= (end - start) * PCPU_MIN_ALLOC_SIZE;

		start = end;
	}

	/*
	 * The negative values are free fragments and thus sorting gives the
	 * free fragments at the beginning in largest first order.
	 */
	if (as_len > 0) {
		sort(alloc_sizes, as_len, sizeof(int), cmpint, NULL);

		/* iterate through the unallocated fragments */
		for (i = 0, p = alloc_sizes; *p < 0 && i < as_len; i++, p++) {
			sum_frag -= *p;
			max_frag = max(max_frag, -1 * (*p));
		}

		cur_min_alloc = alloc_sizes[i];
		cur_med_alloc = alloc_sizes[(i + as_len - 1) / 2];
		cur_max_alloc = alloc_sizes[as_len - 1];
	}

	P("nr_alloc", chunk->nr_alloc);
	P("max_alloc_size", chunk->max_alloc_size);
	P("empty_pop_pages", chunk->nr_empty_pop_pages);
	P("first_bit", chunk->first_bit);
	P("free_bytes", chunk->free_bytes);
	P("contig_bytes", chunk->contig_bits * PCPU_MIN_ALLOC_SIZE);
	P("sum_frag", sum_frag);
	P("max_frag", max_frag);
	P("cur_min_alloc", cur_min_alloc);
	P("cur_med_alloc", cur_med_alloc);
	P("cur_max_alloc", cur_max_alloc);
	seq_putc(m, '\n');
}

static int percpu_stats_show(struct seq_file *m, void *v)
{
	struct pcpu_chunk *chunk;
	int slot, max_nr_alloc;
	int *buffer;

alloc_buffer:
	spin_lock_irq(&pcpu_lock);
	max_nr_alloc = find_max_nr_alloc();
	spin_unlock_irq(&pcpu_lock);

	/* there can be at most this many free and allocated fragments */
	buffer = vmalloc(array_size(sizeof(int), (2 * max_nr_alloc + 1)));
	if (!buffer)
		return -ENOMEM;

	spin_lock_irq(&pcpu_lock);

	/* if the buffer allocated earlier is too small */
	if (max_nr_alloc < find_max_nr_alloc()) {
		spin_unlock_irq(&pcpu_lock);
		vfree(buffer);
		goto alloc_buffer;
	}

#define PL(X) \
	seq_printf(m, "  %-20s: %12lld\n", #X, (long long int)pcpu_stats_ai.X)

	seq_printf(m,
			"Percpu Memory Statistics\n"
			"Allocation Info:\n"
			"----------------------------------------\n");
	PL(unit_size);
	PL(static_size);
	PL(reserved_size);
	PL(dyn_size);
	PL(atom_size);
	PL(alloc_size);
	seq_putc(m, '\n');

#undef PL

#define PU(X) \
	seq_printf(m, "  %-20s: %12llu\n", #X, (unsigned long long)pcpu_stats.X)

	seq_printf(m,
			"Global Stats:\n"
			"----------------------------------------\n");
	PU(nr_alloc);
	PU(nr_dealloc);
	PU(nr_cur_alloc);
	PU(nr_max_alloc);
	PU(nr_chunks);
	PU(nr_max_chunks);
	PU(min_alloc_size);
	PU(max_alloc_size);
	P("empty_pop_pages", pcpu_nr_empty_pop_pages);
	seq_putc(m, '\n');

#undef PU

	seq_printf(m,
			"Per Chunk Stats:\n"
			"----------------------------------------\n");

	if (pcpu_reserved_chunk) {
		seq_puts(m, "Chunk: <- Reserved Chunk\n");
		chunk_map_stats(m, pcpu_reserved_chunk, buffer);
	}

	for (slot = 0; slot < pcpu_nr_slots; slot++) {
		list_for_each_entry(chunk, &pcpu_slot[slot], list) {
			if (chunk == pcpu_first_chunk) {
				seq_puts(m, "Chunk: <- First Chunk\n");
				chunk_map_stats(m, chunk, buffer);


			} else {
				seq_puts(m, "Chunk:\n");
				chunk_map_stats(m, chunk, buffer);
			}

		}
	}

	spin_unlock_irq(&pcpu_lock);

	vfree(buffer);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(percpu_stats);

static int percpu_users_show(struct seq_file *m, void *v)
{
	struct pcpu_allocs_info *allocs, *sum, *cur;
	struct pcpu_chunk *chunk;
	int unit_pages, slot_users, max_users;
	int slot, i;

	unit_pages = pcpu_stats_ai.unit_size >> PAGE_SHIFT;
	slot_users = pcpu_nr_pages_to_map_bits(unit_pages);
	max_users = slot_users * (pcpu_nr_slots + 1);

	allocs = vzalloc(array_size(sizeof(*allocs), max_users));
	if (!allocs)
		return -ENOMEM;

	spin_lock_irq(&pcpu_lock);

	for (slot = 0; slot < pcpu_nr_slots; slot++)
		list_for_each_entry(chunk, &pcpu_slot[slot], list)
			get_chunk_alloc_info(chunk, allocs + slot);

	if (pcpu_reserved_chunk)
		get_chunk_alloc_info(pcpu_reserved_chunk, allocs + slot);

	spin_unlock_irq(&pcpu_lock);

	for (slot = 1; slot < pcpu_nr_slots + 1; slot++) {
		for (i = 0; i < slot_users; i++) {
			sum = &allocs[i];
			cur = &allocs[i + slot * slot_users];

			if (sum->size == cur->size &&
			    sum->caller == cur->caller) {
				sum->count += cur->count;
				cur->size = cur->count = 0;
				cur->caller = NULL;
			}
		}
	}

	for (i = 0; i < max_users; i++)
		if (allocs[i].size)
			seq_printf(m, "%-10ld\t%-10d\t%-30pS\n", allocs[i].size,
				   allocs[i].count, allocs[i].caller);

	vfree(allocs);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(percpu_users);

static int __init init_percpu_stats_debugfs(void)
{
	debugfs_create_file("percpu_stats", 0444, NULL, NULL,
			&percpu_stats_fops);

	debugfs_create_file("percpu_users", 0444, NULL, NULL,
			&percpu_users_fops);

	return 0;
}

late_initcall(init_percpu_stats_debugfs);
