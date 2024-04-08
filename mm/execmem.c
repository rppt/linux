// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/execmem.h>
#include <linux/spinlock.h>
#include <linux/maple_tree.h>
#include <linux/moduleloader.h>
#include <linux/text-patching.h>

#include "internal.h"

extern void __dump_pagetable(unsigned long address);

static void dump_pagetable(const char *msg, unsigned long address)
{
	/* pr_info("---> %s\n", msg); */
	/* __dump_pagetable(address); */
}

static struct execmem_info execmem_info;

static void execmem_invalidate(void *ptr, size_t size)
{
	if (execmem_info.invalidate)
		execmem_info.invalidate(ptr, size);
	else
		memset(ptr, 0, size);
}

struct execmem_cache {
	spinlock_t lock;
	struct maple_tree busy_areas;
	struct maple_tree free_areas;
};

static struct execmem_cache execmem_cache = {
	/* .busy_areas = MTREE_INIT(busy_areas, MT_FLAGS_USE_RCU), */
	/* .free_areas = MTREE_INIT(free_areas, MT_FLAGS_USE_RCU), */
	.lock = __SPIN_LOCK_UNLOCKED(lock),
	.busy_areas = MTREE_INIT(busy_areas, 0),
	.free_areas = MTREE_INIT(free_areas, 0),
};

static int execmem_cache_add(void *ptr, size_t size)
{
	struct maple_tree *free_areas = &execmem_cache.free_areas;
	unsigned long addr = (unsigned long)ptr;
	MA_STATE(mas, free_areas, 0, addr - 1);
	unsigned long lower, lower_size = 0;
	unsigned long upper, upper_size = 0;
	unsigned long entry_size;
	void *entry = NULL;
	int err;

	pr_info("%s: ptr: %p size: %lx\n", __func__, ptr, size);

	lower = addr;
	upper = addr + size - 1;

	spin_lock(&execmem_cache.lock);

	mas_lock(&mas);
	entry = mas_walk(&mas);
	if (entry && xa_is_value(entry) && mas.last == addr - 1) {
		lower = mas.index;
		lower_size = xa_to_value(entry);
	}

	/* pr_info("===> add: addr: %lx index: %lx last: %lx", addr, mas.index, mas.last); */

	entry = mas_next(&mas, ULONG_MAX);
	if (entry && xa_is_value(entry) && mas.index == addr + size) {
		upper = mas.last;
		upper_size = xa_to_value(entry);
	}

	/* pr_info("===> add: addr: %lx index: %lx last: %lx", addr, mas.index, mas.last); */

	entry_size = lower_size + upper_size + size;

	/* pr_info("===> add: lower: %lx upper: %lx size: %lx", lower, upper, entry_size); */

	mas_set_range(&mas, lower, upper);
	err = mas_store_gfp(&mas, xa_mk_value(entry_size), GFP_KERNEL);
	mas_unlock(&mas);

	spin_unlock(&execmem_cache.lock);

	if (err)
		return -ENOMEM;

	return 0;
}

static void *__execmem_cache_alloc(size_t size)
{
	struct maple_tree *free_areas = &execmem_cache.free_areas;
	struct maple_tree *busy_areas = &execmem_cache.busy_areas;
	unsigned long area_start, area_size = 0;
	MA_STATE(mas, free_areas, 0, ULONG_MAX);
	MA_STATE(mas_f, busy_areas, 0, ULONG_MAX);
	void *entry;
	int err;

	spin_lock(&execmem_cache.lock);

	mas_lock(&mas);
	mas_for_each(&mas, entry, ULONG_MAX) {
		if (!xa_is_value(entry)) {
			pr_info("==> not entry at %lx\n", mas.index);
			continue;
		}

		area_size = xa_to_value(entry);
		/* pr_info("===> %lx at %lx\n", area_size, mas.index); */
		if (area_size >= size)
			break;
	}

	if (area_size < size) {
		pr_info("===> %s: !area_size\n", __func__);
		goto out_mas_unlock;
		/* return NULL; */
	}

	area_start = mas.index;

	mas_erase(&mas);
	if (area_size > size) {
		unsigned long area_end = area_start + area_size;
		unsigned long new_size = area_size - size;

		mas_set_range(&mas, area_start + size, area_end - 1);
		err = mas_store_gfp(&mas, xa_mk_value(new_size), GFP_KERNEL);
		if (err) {
			pr_info("===> %s: mas_store: %d\n", __func__, err);
			goto out_mas_unlock;
		}
	}

	mas_unlock(&mas);

	mas_lock(&mas_f);
	mas_set_range(&mas_f, area_start, area_start + size - 1);
	err = mas_store_gfp(&mas_f, xa_mk_value(size), GFP_KERNEL);
	mas_unlock(&mas_f);
	spin_unlock(&execmem_cache.lock);

	if (err) {
		/* FIXME: return area to the cache? */
		pr_info("===> %s: mtree_store: %d\n", __func__, err);
		return NULL;
	}

	return (void *)area_start;

out_mas_unlock:
	mas_unlock(&mas);
	spin_unlock(&execmem_cache.lock);
	return NULL;
}

static void *execmem_cache_alloc(struct execmem_range *range, size_t size)
{
	unsigned long vm_flags = VM_FLUSH_RESET_PERMS | VM_ALLOW_HUGE_VMAP;
	unsigned long start, end;
	struct vm_struct *vm;
	size_t alloc_size;
	void *p;
	int err;

	pr_info("===> %s: size: %lx\n", __func__, size);

retry:
	p = __execmem_cache_alloc(size);
	if (p) {
		pr_info("===> %s: cached ptr: %px\n", __func__, p);
		if ((unsigned long)p & ~PAGE_MASK)
			goto dump;
		return p;
	}

	alloc_size = round_up(size, PMD_SIZE);
	p = __vmalloc_node_range(alloc_size, PMD_SIZE, range->start, range->end,
				 GFP_KERNEL | __GFP_NOWARN, PAGE_KERNEL,
				 vm_flags, NUMA_NO_NODE,
				 __builtin_return_address(0));
	if (p && range->fallback_start)
		p = __vmalloc_node_range(alloc_size, PMD_SIZE,
					 range->fallback_start,
					 range->fallback_end,
					 GFP_KERNEL | __GFP_NOWARN, PAGE_KERNEL,
					 vm_flags, NUMA_NO_NODE,
					 __builtin_return_address(0));
	if (!p)
		return NULL;

	/* do invalidation, remapping etc */
	execmem_invalidate(p, alloc_size);
	vm = find_vm_area(p);
	if (!vm)
		goto err_free_mem;

	start = (unsigned long)p;
	end = (unsigned long)p + alloc_size;
	vunmap_range_noflush(start, end);
	flush_tlb_kernel_range(start, end);

	err = vmap_pages_range_noflush(start, end, PAGE_KERNEL_EXEC, vm->pages,
				       PMD_SHIFT);
	if (err)
		goto err_free_mem;


	dump_pagetable("vmap 2M", start);

	err = execmem_cache_add(p, alloc_size);
	if (err)
		goto err_free_mem;

	goto retry;

	if (alloc_size > size) {
		err = execmem_cache_add(p + size, alloc_size - size);
		if (err)
			goto err_free_mem;
	}

	pr_info("===> %s: pre-cached ptr: %px\n", __func__, p);
	return p;

err_free_mem:
	vfree(p);
	return NULL;

dump:
	pr_info("> ---------- %s: BUSY: ----------\n", __func__);
	mt_dump(&execmem_cache.busy_areas, mt_dump_hex);
	pr_info("\n");
	pr_info("> ---------- %s: FREE: ----------\n", __func__);
	mt_dump(&execmem_cache.free_areas, mt_dump_hex);
	pr_info("< ---------- %s ----------\n", __func__);
	pr_info("\n");

	return p;
}

static bool execmem_cache_free(void *ptr)
{
	struct maple_tree *busy_areas = &execmem_cache.busy_areas;
	void *entry = mtree_load(busy_areas, (unsigned long)ptr);
	size_t size;

	if (!entry)
		return false;

	spin_lock(&execmem_cache.lock);

	pr_info("%s: ptr: %p\n", __func__, ptr);

	size = xa_to_value(entry);
	mtree_erase(busy_areas, (unsigned long)ptr);

	pr_info("%s: size: %lx\n", __func__, size);

	spin_unlock(&execmem_cache.lock);

	/* FIXME: invalidate with poke */
	dump_pagetable("free", (unsigned long)ptr);

	execmem_invalidate(ptr, size);

	execmem_cache_add(ptr, size);

	return true;
}

static void *__execmem_alloc(struct execmem_range *range, size_t size,
			     unsigned long start, unsigned long end)
{
	unsigned int align = range->alignment;
	pgprot_t pgprot = range->pgprot;
	bool kasan = range->flags & EXECMEM_KASAN_SHADOW;
	bool use_cache = range->flags & EXECMEM_CACHED;
	unsigned long vm_flags  = VM_FLUSH_RESET_PERMS;
	gfp_t gfp_flags = GFP_KERNEL | __GFP_NOWARN;

	if (use_cache)
		return execmem_cache_alloc(range, size);

	if (kasan)
		vm_flags |= VM_DEFER_KMEMLEAK;

	return __vmalloc_node_range(size, align, start, end, gfp_flags,
				    pgprot, vm_flags, NUMA_NO_NODE,
				    __builtin_return_address(0));
}

static void *execmem_alloc(struct execmem_range *range, size_t size)
{
	unsigned long start = range->start;
	unsigned long end = range->end;
	unsigned long fallback_start = range->fallback_start;
	unsigned long fallback_end = range->fallback_end;
	bool kasan = range->flags & EXECMEM_KASAN_SHADOW;
	bool fallback  = !!fallback_start;
	void *p;

	if (PAGE_ALIGN(size) > (end - start))
		return NULL;

	p = __execmem_alloc(range, size, start, end);
	if (!p && fallback)
		p = __execmem_alloc(range, size, fallback_start, fallback_end);

	if (!p) {
		pr_warn_ratelimited("execmem: unable to allocate memory\n");
		return NULL;
	}

	if (kasan && (kasan_alloc_module_shadow(p, size, GFP_KERNEL) < 0)) {
		vfree(p);
		return NULL;
	}

	return kasan_reset_tag(p);
}

void *execmem_text_alloc(enum execmem_type type, size_t size)
{
	struct execmem_range *range = &execmem_info.ranges[type];

	return execmem_alloc(range, size);
}

static inline bool execmem_range_is_data(enum execmem_type type)
{
	return type == EXECMEM_MODULE_DATA;
}

void *execmem_data_alloc(enum execmem_type type, size_t size)
{
	struct execmem_range *range = &execmem_info.ranges[type];

	WARN_ON_ONCE(!execmem_range_is_data(type));

	return execmem_alloc(range, size);
}

void execmem_free(void *ptr)
{
	/*
	 * This memory may be RO, and freeing RO memory in an interrupt is not
	 * supported by vmalloc.
	 */
	WARN_ON(in_interrupt());

	if (!execmem_cache_free(ptr))
		vfree(ptr);
}

void *execmem_update_copy(void *dst, const void *src, size_t size)
{
	return text_poke_copy(dst, src, size);
}

bool execmem_is_read_only(enum execmem_type type)
{
	return !!(execmem_info.ranges[type].flags & EXECMEM_READ_ONLY);
}

static bool execmem_validate(struct execmem_info *info)
{
	struct execmem_range *r = &info->ranges[EXECMEM_DEFAULT];

	if (!r->alignment || !r->start || !r->end || !pgprot_val(r->pgprot)) {
		pr_crit("Invalid parameters for execmem allocator, module loading will fail");
		return false;
	}

	return true;
}

static void execmem_init_missing(struct execmem_info *info)
{
	struct execmem_range *default_range = &info->ranges[EXECMEM_DEFAULT];

	for (int i = EXECMEM_DEFAULT + 1; i < EXECMEM_TYPE_MAX; i++) {
		struct execmem_range *r = &info->ranges[i];
		if (!r->start) {
			if (execmem_range_is_data(i))
				r->pgprot = PAGE_KERNEL;
			else
				r->pgprot = default_range->pgprot;
			r->alignment = default_range->alignment;
			r->start = default_range->start;
			r->end = default_range->end;
			r->flags = default_range->flags;
			r->fallback_start = default_range->fallback_start;
			r->fallback_end = default_range->fallback_end;
		}
	}
}

struct execmem_info * __weak execmem_arch_setup(void)
{
	return NULL;
}

static int __init __execmem_init(void)
{
	struct execmem_info *info = execmem_arch_setup();

	if (!info) {
		info = &execmem_info;
		info->ranges[EXECMEM_DEFAULT].start = VMALLOC_START;
		info->ranges[EXECMEM_DEFAULT].end = VMALLOC_END;
		info->ranges[EXECMEM_DEFAULT].pgprot = PAGE_KERNEL_EXEC;
		info->ranges[EXECMEM_DEFAULT].alignment = 1;
		return 0;
	}

	if (!execmem_validate(info))
		return -EINVAL;

	execmem_init_missing(info);

	execmem_info = *info;

	return 0;
}

#ifndef CONFIG_ARCH_WANTS_EXECMEM_EARLY
static int __init execmem_init(void)
{
	return __execmem_init();
}
core_initcall(execmem_init);
#else
void __init execmem_early_init(void)
{
	(void)__execmem_init();
}
#endif
