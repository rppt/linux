/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ASS_H
#define _LINUX_ASS_H

int ass_clone_range(struct mm_struct *mm,
		    pgd_t *pgdp, pgd_t *target_pgdp,
		    unsigned long start, unsigned long end);
int ass_clone_range(struct mm_struct *mm,
		    pgd_t *pgdp, pgd_t *target_pgdp,
		    unsigned long start, unsigned long end);
int ass_free_pagetable(struct task_struct *tsk, pgd_t *ass_pgd);

int ass_make_page_exclusive(struct page *page, unsigned int order);
void ass_unmake_page_exclusive(struct page *page, unsigned int order);

struct ns_pgd *ass_create_ns_pgd(struct mm_struct *mm);

struct kmem_cache *ass_kmem_get_cache(struct kmem_cache *cachep);

struct ns_pgd {
	struct list_head l;
	pgd_t *pgd;
};

extern struct page_ext_operations page_excl_ops;

#endif
