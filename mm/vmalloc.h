/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * mm-internal APIs for vmalloc
 */
#ifndef __MM_VMALLOC_H
#define __MM_VMALLOC_H

#include <linux/set_memory.h>

#ifdef CONFIG_MMU
void __init vmalloc_init(void);
int __must_check vmap_pages_range_noflush(unsigned long addr, unsigned long end,
	pgprot_t prot, struct page **pages, unsigned int page_shift, gfp_t gfp_mask);
unsigned int get_vm_area_page_order(struct vm_struct *vm);
#else
static inline void vmalloc_init(void)
{
}

static inline
int __must_check vmap_pages_range_noflush(unsigned long addr, unsigned long end,
	pgprot_t prot, struct page **pages, unsigned int page_shift, gfp_t gfp_mask)
{
	return -EINVAL;
}

static inline unsigned int get_vm_area_page_order(struct vm_struct *vm)
{
	return 0;
}
#endif

void clear_vm_uninitialized_flag(struct vm_struct *vm);

int __must_check __vmap_pages_range_noflush(unsigned long addr,
			       unsigned long end, pgprot_t prot,
			       struct page **pages, unsigned int page_shift);

void vunmap_range_noflush(unsigned long start, unsigned long end);

void __vunmap_range_noflush(unsigned long start, unsigned long end);

static inline void vm_area_set_direct_map(struct vm_struct *vm,
		int (*set_direct_map)(const void *addr, unsigned long numpages))
{
	unsigned int nr = (1 << get_vm_area_page_order(vm));
	int err = 0;

	for (int i = 0; i < vm->nr_pages; i += nr) {
		err = set_direct_map(page_address(vm->pages[i]), nr);
		WARN_ON_ONCE(err);
	}
}

static inline void vm_area_set_direct_map_invalid(struct vm_struct *vm)
{
	vm_area_set_direct_map(vm, set_direct_map_invalid);
}

static inline void vm_area_set_direct_map_default(struct vm_struct *vm)
{
	vm_area_set_direct_map(vm, set_direct_map_default);
}
#endif /* __MM_VMALLOC_H */
