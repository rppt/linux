// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/execmem.h>
#include <linux/moduleloader.h>

#include "internal.h"

static struct execmem_params execmem_params;

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
}
