// SPDX-License-Identifier: GPL-2.0
#ifndef _INCLUDE_LINUX_ASI_H
#define _INCLUDE_LINUX_ASI_H

#include <linux/slab.h>

enum asi_clone_level {
	ASI_LEVEL_LEAF,
        ASI_LEVEL_PTE,
        ASI_LEVEL_PMD,
        ASI_LEVEL_PUD,
        ASI_LEVEL_P4D,
        ASI_LEVEL_PGD,
};

struct asi_kmalloc {
	struct kmem_cache *caches[NR_KMALLOC_TYPES][KMALLOC_SHIFT_HIGH + 1];
};

struct asi_ctx {
	struct mm_struct *mm;
	pgd_t *pgd;
	struct asi_kmalloc *kmalloc;
};

DECLARE_PER_CPU(struct asi_ctx *, pcpu_asi_ctx);

int asi_clone_pgd_range(struct asi_ctx *asi_ctx,
			pgd_t *src_pagetable,
			unsigned long addr, unsigned long end,
			enum asi_clone_level level);

int asi_map_range(struct asi_ctx *asi_ctx,
		  unsigned long virt, phys_addr_t phys,
		  pgprot_t prot, int nr_pages);

static inline int asi_map_page(struct asi_ctx *asi_ctx,
			       unsigned long virt, phys_addr_t phys,
			       pgprot_t prot)
{
	return asi_map_range(asi_ctx, virt, phys, prot, 1);
}

struct kmem_cache *asi_kmalloc_slab(struct kmem_cache *slab,
				    enum kmalloc_cache_type type,
				    unsigned int idx);

void asi_exit(struct mm_struct *mm);

#endif /* _INCLUDE_LINUX_ASI_H */
