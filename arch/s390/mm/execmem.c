// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>
#include <linux/kasan.h>
#include <linux/execmem.h>
#include <linux/vmalloc.h>
/* FIXME: MODULE_ALIGN */
#include <linux/moduleloader.h>

static unsigned long get_execmem_load_offset(void)
{
	static DEFINE_MUTEX(execmem_kaslr_mutex);
	static unsigned long execmem_load_offset;

	if (!kaslr_enabled())
		return 0;
	/*
	 * Calculate the execmem_load_offset the first time this code
	 * is called. Once calculated it stays the same until reboot.
	 */
	mutex_lock(&execmem_kaslr_mutex);
	if (!execmem_load_offset)
		execmem_load_offset = get_random_u32_inclusive(1, 1024) * PAGE_SIZE;
	mutex_unlock(&execmem_kaslr_mutex);
	return execmem_load_offset;
}

void *execmem_alloc(size_t size)
{
	gfp_t gfp_mask = GFP_KERNEL;
	void *p;

	if (PAGE_ALIGN(size) > MODULES_LEN)
		return NULL;
	p = __vmalloc_node_range(size, MODULE_ALIGN,
				 MODULES_VADDR + get_execmem_load_offset(),
				 MODULES_END, gfp_mask, PAGE_KERNEL,
				 VM_FLUSH_RESET_PERMS | VM_DEFER_KMEMLEAK,
				 NUMA_NO_NODE, __builtin_return_address(0));
	if (p && (kasan_alloc_module_shadow(p, size, gfp_mask) < 0)) {
		vfree(p);
		return NULL;
	}
	return p;
}
