// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/execmem.h>
#include <linux/moduleloader.h>

struct execmem_params execmem_params;

static void *execmem_alloc(size_t size, struct execmem_range *range)
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

void *execmem_text_alloc(size_t size)
{
	return execmem_alloc(size, &execmem_params.modules.text);
}

void *execmem_data_alloc(size_t size)
{
	return execmem_alloc(size, &execmem_params.modules.data);
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

void *jit_text_alloc(size_t size)
{
	return execmem_text_alloc(size);
}

void jit_free(void *ptr)
{
	execmem_free(ptr);
}

struct execmem_params * __weak execmem_arch_params(void)
{
	return NULL;
}

static bool execmem_validate_params(struct execmem_params *p)
{
	struct execmem_modules_range *m = &p->modules;
	struct execmem_range *t = &m->text;

	if (!t->alignment || !t->start || !t->end || !pgprot_val(t->pgprot)) {
		pr_crit("Invalid parameters for execmem allocator, module loading will fail");
		return false;
	}

	return true;
}

static void execmem_init_missing(struct execmem_params *p)
{
	struct execmem_range *text = &p->modules.text;
	struct execmem_range *data = &p->modules.data;

	if (!data->start) {
		data->pgprot = PAGE_KERNEL;
		data->alignment = text->alignment;
		data->start = text->start;
		data->end = text->end;
		data->fallback_start = text->fallback_start;
		data->fallback_end = text->fallback_end;
	}
}

void __init execmem_init(void)
{
	struct execmem_params *p = execmem_arch_params();

	if (!p) {
		p = &execmem_params;
		p->modules.text.start = VMALLOC_START;
		p->modules.text.end = VMALLOC_END;
		p->modules.text.pgprot = PAGE_KERNEL_EXEC;
		p->modules.text.alignment = 1;

		p->modules.data.start = VMALLOC_START;
		p->modules.data.end = VMALLOC_END;
		p->modules.data.pgprot = PAGE_KERNEL;
		p->modules.data.alignment = 1;

		return;
	}

	if (!execmem_validate_params(p))
		return;

	execmem_params = *p;

	execmem_init_missing(&execmem_params);
}
