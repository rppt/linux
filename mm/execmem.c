// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/list.h>
#include <linux/vmalloc.h>
#include <linux/execmem.h>
#include <linux/spinlock.h>
#include <linux/set_memory.h>
#include <linux/maple_tree.h>
#include <linux/moduleloader.h>

#include "internal.h"

/* FIXME: have PMD_ORDER at last available in include/linux */
#define PMD_ORDER	(PMD_SHIFT - PAGE_SHIFT)
#define MODULES_ALIGN(x)	ALIGN((x), MODULE_ALIGN)

/* #define FREE_AREA_COUNT (PMD_SIZE/MODULE_ALIGN + 1) */
#define FREE_AREA_COUNT 513

static struct execmem_params execmem_params;
struct exm_area {
	unsigned long start;
	size_t size;
	struct list_head list;
};

struct execmem_free_list {
	struct list_head head;
};

struct execmem_cache {
	spinlock_t lock;
	struct maple_tree busy_mt;
	struct maple_tree free_mt;
	struct execmem_free_list free_area[FREE_AREA_COUNT];
};

static struct execmem_cache execmem_cache = {
	.busy_mt = MTREE_INIT(busy_mt, 0),
	.free_mt = MTREE_INIT(free_mt, 0),
};

static void execmem_cache_dump(void)
{
	struct exm_area *area;
	unsigned long index = 0;
	void *entry;

	pr_info("free maple tree:\n");
	mt_for_each(&execmem_cache.free_mt, area, index, ULONG_MAX) {
		pr_info("i: %lx addr: %lx end: %lx size: %lx\n", index & ~7, area->start, area->start + area->size, area->size);
	}

	pr_info("free lists:\n");
	for (int i = 0; i < ARRAY_SIZE(execmem_cache.free_area); i++) {
		struct execmem_free_list *list = &execmem_cache.free_area[i];

		if (!list) {
			pr_info("i: %d NULL\n", i);
			continue;
		}

		if (list_empty(&list->head))
			continue;

		pr_info("i: %d:", i);
		list_for_each_entry(area, &list->head, list) {
			pr_info("\taddr: %lx end: %lx size: %lx\n", area->start, area->start + area->size, area->size);
		}
	}

	index = 0;
	pr_info("busy maple tree:\n");
	mt_for_each(&execmem_cache.busy_mt, entry, index, ULONG_MAX) {
		unsigned long addr = index & ~7;
		size_t size;

		if (!xa_is_value(entry)) {
			pr_info("not value at %lx\n", index);
			continue;
		}

		size = xa_to_value(entry);
		pr_info("addr: %lx end: %lx size: %lx\n", addr, addr + size, size);
	}
}

#define bug_on(cond)					\
	if ((cond)) {					\
		execmem_cache_dump();			\
		BUG();					\
	}

static int execmem_cache_add(void *ptr, size_t size)
{
	struct maple_tree *mt = &execmem_cache.free_mt;
	unsigned long addr = (unsigned long)ptr;
	struct exm_area *entry, *upper, *lower;
	struct execmem_free_list *free_list;
	unsigned long index, lower_index, upper_index;
	size_t lower_sz = 0, upper_sz = 0;
	bool merge_prev = false;
	bool merge_next = false;
	size_t asize;
	int err;

	pr_debug("%s: adding %lx at %p\n", __func__, size, ptr);

	index = 0;
	lower = mt_find(mt, &index, addr - 1);
	if (lower) {
		lower_sz = lower->size;
		lower_index = index;

		if (index + lower_sz == addr) {
			lower->size = size + lower_sz;
			list_del_init(&lower->list);

			err = mtree_store(mt, lower_index, lower, GFP_KERNEL);
			bug_on(err);

			merge_prev = true;
		}
	}

	index++;
	upper = mt_find_after(mt, &index, ULONG_MAX);
	if (upper) {
		upper_sz = upper->size;
		upper_index = index;

		if (addr + size == upper_index) {
			unsigned long sz = size + upper_sz;

			list_del_init(&upper->list);
			mtree_erase(mt, upper_index);

			if (merge_prev) {
				sz += lower_sz;
			} else {
				index = addr;
			}

			upper->size = sz;
			upper->start = index;
			entry = upper;

			err = mtree_store(mt, index, entry, GFP_KERNEL);
			bug_on(err);

			merge_next = true;
		}
	}

	if (!merge_prev && !merge_next) {
		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
		entry->start = addr;
		entry->size = size;
		INIT_LIST_HEAD(&entry->list);

		err = mtree_store(mt, addr, entry, GFP_KERNEL);
		bug_on(err);
	}

	asize = entry->size >> PAGE_SHIFT;
	free_list = &execmem_cache.free_area[asize];
	list_add(&entry->list, &free_list->head);

	return 0;
}

static void *execmem_cache_alloc(size_t size)
{
	struct maple_tree *free_mt = &execmem_cache.free_mt;
	struct maple_tree *busy_mt = &execmem_cache.busy_mt;
	size_t asize = size >> PAGE_SHIFT;
	struct exm_area *entry, *entry1;
	/* struct ma_state mas; */
	void *ptr = NULL;

	for (int i = asize; i < ARRAY_SIZE(execmem_cache.free_area); i++) {
		struct list_head *head = &execmem_cache.free_area[i].head;
		unsigned long addr;
		int err;

		if (list_empty(head))
			continue;

		entry = list_first_entry(head, struct exm_area, list);

		addr = entry->start;
		list_del_init(&entry->list);

		entry1 = mtree_load(free_mt, addr);
		bug_on(!entry1);
		bug_on(entry != entry1);
		mtree_erase(free_mt, addr);

		if (i > asize) {
			execmem_cache_add((void *)(entry->start + size),
					  entry->size - size);
		}

		pr_debug("%s: busy: adding %lx at %lx\n", __func__, size, addr);
		err = mtree_insert(busy_mt, addr, xa_mk_value(size), GFP_KERNEL);
		if (err) {
			pr_err("insert busy failed: %d\n", err);
			execmem_cache_dump();
			bug_on(err);
		}

		ptr = (void *)addr;
		break;
	}

	return ptr;
}

static void execmem_free_cached(void *ptr)
{
	struct maple_tree *busy_mt = &execmem_cache.busy_mt;
	void *entry = mtree_load(busy_mt, (unsigned long)ptr);
	size_t size;

	bug_on(!entry);
	bug_on(!xa_is_value(entry));

	size = xa_to_value(entry);
	mtree_erase(busy_mt, (unsigned long)ptr);

	execmem_cache_add(ptr, size);
}

static void execmem_cache_init(void)
{
	for (int i = 0; i < ARRAY_SIZE(execmem_cache.free_area); i++) {
		struct execmem_free_list *l = &execmem_cache.free_area[i];

		INIT_LIST_HEAD(&l->head);
	}
	spin_lock_init(&execmem_cache.lock);
}

static void *execmem_alloc_cached(size_t size, struct execmem_range *range,
				  gfp_t gfp_flags)
{
	unsigned long vm_flags = VM_FLUSH_RESET_PERMS | VM_NO_GUARD;
	unsigned long start = range->start;
	unsigned long end = range->end;
	unsigned int align = range->alignment;
	pgprot_t pgprot = range->pgprot;
	unsigned long addr;
	size_t alloc_size;
	void *ptr;
	int err;

	/* try the cache first */
	size = MODULES_ALIGN(size);
	ptr = execmem_cache_alloc(size);
	if (ptr) {
		__set_memory_prot((unsigned long)ptr, size, pgprot);
		return ptr;
	}

	/* try allocating large pages that cover the requested size */
	alloc_size = ALIGN(size, PMD_SIZE);
	/* vm_flags |= VM_ALLOW_HUGE_VMAP; */
	ptr =  __vmalloc_node_range(alloc_size, PMD_SIZE, start, end, gfp_flags,
				    pgprot, vm_flags, NUMA_NO_NODE,
				    __builtin_return_address(0));
	if (!ptr) {
		/* /\* if requested size cannot be allocated, nothing to do *\/ */
		/* if (alloc_size == size) */
		/* 	return NULL; */

		/* /\* try getting exact size, screw large pages *\/ */
		/* vm_flags &= ~VM_ALLOW_HUGE_VMAP; */
		/* ptr =  __vmalloc_node_range(size, align, start, end, gfp_flags, */
		/* 			     pgprot, vm_flags, NUMA_NO_NODE, */
		/* 			     __builtin_return_address(0)); */
		if (!ptr)
			return NULL;
	}

	/* add extra memory (if any) to the cache */
	if (alloc_size > size) {
		err = execmem_cache_add(ptr + size, alloc_size - size);
		if (err) {
			vfree(ptr);
			return NULL;
		}
	}

	/* record the allocated pointer */
	addr = (unsigned long)ptr;
	err = mtree_insert(&execmem_cache.busy_mt, addr, xa_mk_value(size),
			   GFP_KERNEL);
	bug_on(err == -EEXIST);
	if (err) {
		/* FIXME: remove from cache */
		vfree(ptr);
		return NULL;
	}

	return ptr;
}

static void *execmem_alloc_unmapped(size_t size, struct execmem_range *range,
				    gfp_t gfp_flags)
{
	unsigned long start = range->start;
	unsigned long end = range->end;
	unsigned long align = range->alignment;
	pgprot_t pgprot = range->pgprot;
	struct vm_struct *area;
	int order, nr_pages;
	struct page *page, **pages;

	align = max(align, PAGE_SIZE);
	size = PAGE_ALIGN(size);
	order = get_order(size);
	nr_pages = size >> PAGE_SHIFT;

	page = unmapped_pages_alloc(gfp_flags, order);
	if (!page)
		return NULL;

	pages = kmalloc_array(nr_pages, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		goto err_free_unmapped_page;

	area = __get_vm_area_caller(size, align, VM_NO_GUARD, start, end,
				    __builtin_return_address(0));
	if (!area)
		goto err_free_pages_array;

	for (int i = 0; i < (1U << order); i++)
		pages[i] = page + i;

	start = (unsigned long)area->addr;
	end = start + size;
	if (vmap_pages_range_noflush(start, end, pgprot, pages, PAGE_SHIFT))
		goto err_free_area;

	flush_cache_vmap(start, end);
	area->pages = pages;
	area->nr_pages = nr_pages;

	return area->addr;

err_free_area:
	free_vm_area(area);
err_free_pages_array:
	kfree(area->pages);
err_free_unmapped_page:
	unmapped_pages_free(page, order);
	return NULL;
}

static void execmem_free_unmapped(void *ptr)
{
	struct vm_struct *area = find_vm_area(ptr);
	int order = get_order(area->nr_pages << PAGE_SHIFT);

	unmapped_pages_free(area->pages[0], order);
	free_vm_area(area);
}

static void *__execmem_alloc(size_t size, struct execmem_range *range,
			     gfp_t gfp_flags, unsigned long vm_flags)
{
	unsigned long start = range->start;
	unsigned long end = range->end;
	unsigned int align = range->alignment;
	pgprot_t pgprot = range->pgprot;

	if (range->flags & EXECMEM_UNMAPPED)
		return execmem_alloc_unmapped(size, range, gfp_flags);

	if (range->flags & EXECMEM_CACHED)
		return execmem_alloc_cached(size, range, gfp_flags);

	return __vmalloc_node_range(size, align, start, end, gfp_flags,
				    pgprot, vm_flags, NUMA_NO_NODE,
				    __builtin_return_address(0));
}

static void *execmem_alloc(size_t size, struct execmem_range *range)
{
	unsigned long start = range->start;
	unsigned long end = range->end;
	unsigned long fallback_start = range->fallback_start;
	unsigned long fallback_end = range->fallback_end;
	bool kasan = range->flags & EXECMEM_KASAN_SHADOW;
	unsigned long vm_flags  = VM_FLUSH_RESET_PERMS;
	bool fallback  = !!fallback_start;
	gfp_t gfp_flags = GFP_KERNEL;
	void *p;

	if (PAGE_ALIGN(size) > (end - start))
		return NULL;

	if (kasan)
		vm_flags |= VM_DEFER_KMEMLEAK;

	if (fallback)
		gfp_flags |= __GFP_NOWARN;

	p = __execmem_alloc(size, range, gfp_flags, vm_flags);
	if (!p && fallback) {
		start = fallback_start;
		end = fallback_end;
		gfp_flags = GFP_KERNEL;

		p = __execmem_alloc(size, range, gfp_flags, vm_flags);
	}

	if (p && kasan &&
	    (kasan_alloc_module_shadow(p, size, GFP_KERNEL) < 0)) {
		vfree(p);
		return NULL;
	}

	return kasan_reset_tag(p);
}

void *execmem_text_alloc(enum execmem_type type, size_t size)
{
	return execmem_alloc(size, &execmem_params.ranges[type]);
}

void *execmem_data_alloc(enum execmem_type type, size_t size)
{
	WARN_ON_ONCE(type != EXECMEM_MODULE_DATA);

	return execmem_alloc(size, &execmem_params.ranges[type]);
}

void execmem_free(void *ptr)
{
	unsigned long addr = (unsigned long)ptr;

	/*
	 * This memory may be RO, and freeing RO memory in an interrupt is not
	 * supported by vmalloc.
	 */
	WARN_ON(in_interrupt());

	for (int i = 0; i < ARRAY_SIZE(execmem_params.ranges); i++) {
		struct execmem_range *range = &execmem_params.ranges[i];

		if ((addr >= range->start && addr < range->end) &&
		    range->flags & EXECMEM_CACHED) {
			execmem_free_cached(ptr);
			return;
		}

		if ((addr >= range->start && addr < range->end) &&
		    range->flags & EXECMEM_UNMAPPED) {
			execmem_free_unmapped(ptr);
			return;
		}
	}

	vfree(ptr);
}

struct execmem_params * __weak execmem_arch_params(void)
{
	return NULL;
}

static bool execmem_validate_params(struct execmem_params *p)
{
	struct execmem_range *r = &p->ranges[EXECMEM_DEFAULT];

	if (!r->alignment || !r->start || !r->end || !pgprot_val(r->pgprot)) {
		pr_crit("Invalid parameters for execmem allocator, module loading will fail");
		return false;
	}

	return true;
}

static inline bool execmem_range_is_data(enum execmem_type type)
{
	return type == EXECMEM_MODULE_DATA;
}

static void execmem_init_missing(struct execmem_params *p)
{
	struct execmem_range *default_range = &p->ranges[EXECMEM_DEFAULT];

	for (int i = EXECMEM_DEFAULT + 1; i < EXECMEM_TYPE_MAX; i++) {
		struct execmem_range *r = &p->ranges[i];

		if (!r->start) {
			if (execmem_range_is_data(i))
				r->pgprot = PAGE_KERNEL;
			else
				r->pgprot = default_range->pgprot;
			r->alignment = default_range->alignment;
			r->start = default_range->start;
			r->end = default_range->end;
			r->fallback_start = default_range->fallback_start;
			r->fallback_end = default_range->fallback_end;
			r->flags = default_range->flags;
		}
	}
}

void __init execmem_init(void)
{
	struct execmem_params *p = execmem_arch_params();

	if (!p) {
		p = &execmem_params;
		p->ranges[EXECMEM_MODULE_TEXT].start = VMALLOC_START;
		p->ranges[EXECMEM_MODULE_TEXT].end = VMALLOC_END;
		p->ranges[EXECMEM_MODULE_TEXT].pgprot = PAGE_KERNEL_EXEC;
		p->ranges[EXECMEM_MODULE_TEXT].alignment = 1;

		p->ranges[EXECMEM_MODULE_DATA].start = VMALLOC_START;
		p->ranges[EXECMEM_MODULE_DATA].end = VMALLOC_END;
		p->ranges[EXECMEM_MODULE_DATA].pgprot = PAGE_KERNEL;
		p->ranges[EXECMEM_MODULE_DATA].alignment = 1;

		return;
	}

	if (!execmem_validate_params(p))
		return;

	execmem_params = *p;

	execmem_init_missing(&execmem_params);
	execmem_cache_init();
}
