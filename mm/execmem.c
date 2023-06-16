// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/execmem.h>
#include <linux/moduleloader.h>

static struct execmem_params execmem_params;
static struct execmem_range default_range;

static void *execmem_alloc(struct execmem_range *range, size_t size)
{
	unsigned long start = range->start;
	unsigned long end = range->end;
	unsigned long fallback_start = range->fallback_start;
	unsigned long fallback_end = range->fallback_end;
	unsigned int align = range->alignment;
	pgprot_t pgprot = range->pgprot;
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

	p = __vmalloc_node_range(size, align, start, end, gfp_flags,
				 pgprot, vm_flags, NUMA_NO_NODE,
				 __builtin_return_address(0));

	if (!p && fallback) {
		start = fallback_start;
		end = fallback_end;
		gfp_flags = GFP_KERNEL;

		p = __vmalloc_node_range(size, align, start, end, gfp_flags,
					 pgprot, vm_flags, NUMA_NO_NODE,
					 __builtin_return_address(0));
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
	unsigned int area = execmem_params.areas[type];

	if (!execmem_params.ranges[area].start)
		return module_alloc(size);

	return execmem_alloc(&execmem_params.ranges[area], size);
}

void execmem_free(void *ptr)
{
	/*
	 * This memory may be RO, and freeing RO memory in an interrupt is not
	 * supported by vmalloc.
	 */
	WARN_ON(in_interrupt());
	vfree(ptr);
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

void __weak execmem_arch_params(struct execmem_params *p)
{
	p->ranges = &default_range;
	p->ranges[EXECMEM_DEFAULT].start = VMALLOC_START;
	p->ranges[EXECMEM_DEFAULT].end = VMALLOC_END;
	p->ranges[EXECMEM_DEFAULT].pgprot = PAGE_KERNEL_EXEC;
	p->ranges[EXECMEM_DEFAULT].alignment = 1;
}


static int __init __execmem_init(void)
{
	execmem_arch_params(&execmem_params);

	if (!execmem_validate_params(&execmem_params))
		return -EINVAL;

	return 0;
}

#ifndef ARCH_WANTS_EXECMEM_EARLY
static int __init execmem_init(void)
{
	return __execmem_init();
}
core_initcall(execmem_init);
#else
int __init execmem_early_init(void)
{
	__execmem_init();
}
#endif
