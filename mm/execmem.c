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
	unsigned int align = range->alignment;
	pgprot_t pgprot = range->pgprot;

	return __vmalloc_node_range(size, align, start, end,
				   GFP_KERNEL, pgprot, VM_FLUSH_RESET_PERMS,
				   NUMA_NO_NODE, __builtin_return_address(0));
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


static int __init execmem_init(void)
{
	execmem_arch_params(&execmem_params);

	if (!execmem_validate_params(&execmem_params))
		return -EINVAL;

	return 0;
}
core_initcall(execmem_init)
