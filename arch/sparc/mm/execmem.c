// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/execmem.h>

static struct execmem_range execmem_ranges[] __ro_after_init = {
	[EXECMEM_DEFAULT] = {
#ifdef CONFIG_SPARC64
		.start = MODULES_VADDR,
		.end = MODULES_END,
#else
		.start = VMALLOC_START,
		.end = VMALLOC_END,
#endif
		.alignment = 1,
	},
};

void __init execmem_arch_params(struct execmem_params *p)
{
	p->ranges = execmem_ranges;
}
