// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>
#include <linux/execmem.h>
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

static void execmem_invalidate(void *ptr, size_t size, bool writable)
{
	if (execmem_info.invalidate)
		execmem_info.invalidate(ptr, size, writable);
	else
		memset(ptr, 0, size);
}

static void *execmem_vmalloc(struct execmem_range *range, size_t size,
			     pgprot_t pgprot, unsigned long vm_flags)
{
	bool kasan = range->flags & EXECMEM_KASAN_SHADOW;
	gfp_t gfp_flags = GFP_KERNEL | __GFP_NOWARN;
	unsigned int align = range->alignment;
	unsigned long start = range->start;
	unsigned long end = range->end;
	void *p;

	if (kasan)
		vm_flags |= VM_DEFER_KMEMLEAK;

	if (vm_flags & VM_ALLOW_HUGE_VMAP)
		align = PMD_SIZE;

	p = __vmalloc_node_range(size, align, start, end, gfp_flags, pgprot,
				 vm_flags, NUMA_NO_NODE,
				 __builtin_return_address(0));
	if (!p && range->fallback_start) {
		start = range->fallback_start;
		end = range->fallback_end;
		p = __vmalloc_node_range(size, align, start, end, gfp_flags,
					 pgprot, vm_flags, NUMA_NO_NODE,
					 __builtin_return_address(0));
	}

	if (!p) {
		pr_warn_ratelimited("execmem: unable to allocate memory\n");
		return NULL;
	}

	if (kasan && (kasan_alloc_module_shadow(p, size, GFP_KERNEL) < 0)) {
		vfree(p);
		return NULL;
	}

	return p;
}

struct execmem_cache {
	struct mutex mutex;
	struct maple_tree busy_areas;
	struct maple_tree free_areas;
};

static struct execmem_cache execmem_cache = {
	.mutex = __MUTEX_INITIALIZER(execmem_cache.mutex),
	.busy_areas = MTREE_INIT(busy_areas, MT_FLAGS_LOCK_EXTERN),
	.free_areas = MTREE_INIT(free_areas, MT_FLAGS_LOCK_EXTERN),
};

static int execmem_cache_add(void *ptr, size_t size)
{
	struct maple_tree *free_areas = &execmem_cache.free_areas;
	struct mutex *mutex = &execmem_cache.mutex;
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

	mutex_lock(mutex);

	/* mas_lock(&mas); */
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
	/* mas_unlock(&mas); */

	mutex_unlock(mutex);

	if (err)
		return -ENOMEM;

	return 0;
}

static void *__execmem_cache_alloc(size_t size)
{
	struct maple_tree *free_areas = &execmem_cache.free_areas;
	struct maple_tree *busy_areas = &execmem_cache.busy_areas;
	MA_STATE(mas_free, free_areas, 0, ULONG_MAX);
	MA_STATE(mas_busy, busy_areas, 0, ULONG_MAX);
	struct mutex *mutex = &execmem_cache.mutex;
	unsigned long area_start, area_size = 0;
	void *area;
	int err;

	mutex_lock(mutex);

	/* mas_lock(&mas); */
	mas_for_each(&mas_free, area, ULONG_MAX) {
		if (!xa_is_value(area)) {
			pr_info("==> not area at %lx\n", mas_free.index);
			continue;
		}

		area_size = xa_to_value(area);
		/* pr_info("===> %lx at %lx\n", area_size, mas.index); */
		if (area_size >= size)
			break;
	}

	if (area_size < size) {
		pr_info("===> %s: !area_size\n", __func__);
		goto out_mas_unlock;
		/* return NULL; */
	}

	area_start = mas_free.index;

	mas_set_range(&mas_busy, area_start, area_start + size - 1);
	err = mas_store_gfp(&mas_busy, xa_mk_value(size), GFP_KERNEL);
	if (err) {
		pr_info("===> %s: mtree_store: %d\n", __func__, err);
		return NULL;
	}

	mas_erase(&mas_free);
	if (area_size > size) {
		unsigned long last = area_start + area_size - 1;
		void *new_size = xa_mk_value(area_size - size);

		mas_set_range(&mas_free, area_start + size, last);
		err = mas_store_gfp(&mas_free, new_size, GFP_KERNEL);
		if (err) {
			mas_erase(&mas_busy);
			pr_info("===> %s: mas_store: %d\n", __func__, err);
			goto out_mas_unlock;
		}
	}

	/* mas_unlock(&mas); */

	/* mas_lock(&mas_busy); */
	/* mas_set_range(&mas_busy, area_start, area_start + size - 1); */
	/* err = mas_store_gfp(&mas_busy, xa_mk_value(size), GFP_KERNEL); */
	/* mas_unlock(&mas_busy); */
	mutex_unlock(mutex);

	return (void *)area_start;

out_mas_unlock:
	/* mas_unlock(&mas); */
	mutex_unlock(mutex);
	return NULL;
}

static int execmem_cache_populate(struct execmem_range *range, size_t size)
{
	unsigned long vm_flags = VM_FLUSH_RESET_PERMS | VM_ALLOW_HUGE_VMAP;
	unsigned long start, end;
	struct vm_struct *vm;
	size_t alloc_size;
	int err = -ENOMEM;
	void *p;

	alloc_size = round_up(size, PMD_SIZE);
	p = execmem_vmalloc(range, alloc_size, PAGE_KERNEL, vm_flags);
	if (!p)
		return err;

	vm = find_vm_area(p);
	if (!vm)
		goto err_free_mem;

	/* fill memory with invalid instructions */
	execmem_invalidate(p, alloc_size, /* writable = */ true);

	start = (unsigned long)p;
	end = start + alloc_size;

	vunmap_range_noflush(start, end);
	flush_tlb_kernel_range(start, end);

	err = vmap_pages_range_noflush(start, end, range->pgprot, vm->pages,
				       PMD_SHIFT);
	if (err)
		goto err_free_mem;

	err = execmem_cache_add(p, alloc_size);
	if (err)
		goto err_free_mem;

	return 0;

err_free_mem:
	vfree(p);
	return err;
}

static void *execmem_cache_alloc(struct execmem_range *range, size_t size)
{
	/* unsigned long vm_flags = VM_FLUSH_RESET_PERMS | VM_ALLOW_HUGE_VMAP; */
	/* unsigned long start, end; */
	/* struct vm_struct *vm; */
	/* size_t alloc_size; */
	void *p;
	int err;

	pr_info("===> %s: size: %lx\n", __func__, size);

	p = __execmem_cache_alloc(size);
	if (p) {
		pr_info("===> %s: cached ptr: %px\n", __func__, p);
		if ((unsigned long)p & ~PAGE_MASK)
			goto dump;
		return p;
	}

	err = execmem_cache_populate(range, size);
	if (err)
		return NULL;

	return __execmem_cache_alloc(size);

	/* alloc_size = round_up(size, PMD_SIZE); */
	/* p = execmem_vmalloc(range, alloc_size, PAGE_KERNEL, vm_flags); */
	/* if (!p) */
	/* 	return NULL; */

	/* do invalidation, remapping etc */
/* 	execmem_invalidate(p, alloc_size); */
/* 	vm = find_vm_area(p); */
/* 	if (!vm) */
/* 		goto err_free_mem; */

/* 	start = (unsigned long)p; */
/* 	end = (unsigned long)p + alloc_size; */
/* 	vunmap_range_noflush(start, end); */
/* 	flush_tlb_kernel_range(start, end); */

/* 	err = vmap_pages_range_noflush(start, end, PAGE_KERNEL_EXEC, vm->pages, */
/* 				       PMD_SHIFT); */
/* 	if (err) */
/* 		goto err_free_mem; */


/* 	dump_pagetable("vmap 2M", start); */

/* 	err = execmem_cache_add(p, alloc_size); */
/* 	if (err) */
/* 		goto err_free_mem; */

/* 	goto retry; */

/* 	if (alloc_size > size) { */
/* 		err = execmem_cache_add(p + size, alloc_size - size); */
/* 		if (err) */
/* 			goto err_free_mem; */
/* 	} */

/* 	pr_info("===> %s: pre-cached ptr: %px\n", __func__, p); */
/* 	return p; */

/* err_free_mem: */
/* 	vfree(p); */
/* 	return NULL; */

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
	struct mutex *mutex = &execmem_cache.mutex;
	void *entry;
	size_t size;

	mutex_lock(mutex);

	pr_info("%s: ptr: %p\n", __func__, ptr);
	entry = mtree_load(busy_areas, (unsigned long)ptr);

	if (!entry) {
		mutex_unlock(mutex);
		return false;
	}

	size = xa_to_value(entry);
	mtree_erase(busy_areas, (unsigned long)ptr);

	pr_info("%s: size: %lx\n", __func__, size);

	mutex_unlock(mutex);

	/* FIXME: invalidate with poke */
	dump_pagetable("free", (unsigned long)ptr);

	execmem_invalidate(ptr, size, /* writable = */ false);

	execmem_cache_add(ptr, size);

	return true;
}

static void *execmem_alloc(struct execmem_range *range, size_t size)
{
	bool use_cache = range->flags & EXECMEM_CACHED;
	unsigned long vm_flags = VM_FLUSH_RESET_PERMS;
	pgprot_t pgprot = range->pgprot;
	void *p;

	if (use_cache)
		p = execmem_cache_alloc(range, size);
	else
		p = execmem_vmalloc(range, size, pgprot, vm_flags);

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
