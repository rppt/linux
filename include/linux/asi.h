// SPDX-License-Identifier: GPL-2.0
#ifndef _INCLUDE_LINUX_ASI_H
#define _INCLUDE_LINUX_ASI_H

#include <linux/list.h>

enum asi_clone_level {
	ASI_LEVEL_LEAF,
        ASI_LEVEL_PTE,
        ASI_LEVEL_PMD,
        ASI_LEVEL_PUD,
        ASI_LEVEL_P4D,
        ASI_LEVEL_PGD,
};

struct asi_kmem_caches;

struct asi_ctx {
	struct asi_kmem_caches *kmem_caches;
	struct mm_struct *mm;
	pgd_t *pgd;
};

int asi_clone_pgd_range(struct asi_ctx *asi_ctx,
			pgd_t *src_pagetable,
			unsigned long addr, unsigned long end,
			enum asi_clone_level level);

int asi_map_range(struct asi_ctx *asi_ctx,
		  unsigned long virt, phys_addr_t phys,
		  pgprot_t prot, int nr_pages);

void asi_unmap_range(struct asi_ctx *asi_ctx, unsigned long virt, int nr_pages);

static inline int asi_map_page(struct asi_ctx *asi_ctx,
			       unsigned long virt, phys_addr_t phys,
			       pgprot_t prot)
{
	return asi_map_range(asi_ctx, virt, phys, prot, 1);
}

int asi_mm_init(struct mm_struct *mm);
void asi_mm_fini(struct mm_struct *mm);
void asi_exit(struct mm_struct *mm);

struct kmem_cache *asi_get_kmem_cache(struct kmem_cache *cache, size_t size,
				      gfp_t flags);

int asi_init_slab(struct asi_ctx *asi);

#endif /* _INCLUDE_LINUX_ASI_H */
