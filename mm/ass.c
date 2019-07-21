// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/sizes.h>
#include <linux/random.h>
#include <linux/cpu.h>
#include <linux/ass.h>

#include <asm/pgalloc.h>

#include "slab.h"

/*
 * Walk the shadow copy of the page tables to PMD level (optionally)
 * trying to allocate page table pages on the way down.
 *
 * Allocation failures are not handled here because the entire page
 * table will be freed in ass_free_pagetable.
 *
 * Returns a pointer to a PMD on success, or NULL on failure.
 */
static pmd_t *ass_pagetable_walk_pmd(struct mm_struct *mm,
				     pgd_t *pgd, unsigned long address)
{
	p4d_t *p4d;
	pud_t *pud;

	p4d = p4d_alloc(mm, pgd, address);
	if (!p4d)
		return NULL;

	pud = pud_alloc(mm, p4d, address);
	if (!pud)
		return NULL;

	return pmd_alloc(mm, pud, address);
}

/*
 * Walk the shadow copy of the page tables to PTE level (optionally)
 * trying to allocate page table pages on the way down.
 *
 * Returns a pointer to a PTE on success, or NULL on failure.
 */
static pte_t *ass_pagetable_walk_pte(struct mm_struct *mm,
				     pgd_t *pgd, unsigned long address)
{
	pmd_t *pmd = ass_pagetable_walk_pmd(mm, pgd, address);

	if (!pmd)
		return NULL;

	if (__pte_alloc(mm, pmd))
		return NULL;

	return pte_offset_kernel(pmd, address);
}

/*
 * Clone a single page mapping
 *
 * The new mapping in the @target_pgdp is always created for base
 * page. If the orinal page table has the page at @addr mapped at PMD
 * level, we anyway create at PTE in the target page table and map
 * only PAGE_SIZE.
 */
pte_t *ass_clone_page(struct mm_struct *mm,
		      pgd_t *pgdp, pgd_t *target_pgdp,
		      unsigned long addr)
{
	pte_t *pte, *target_pte, ptev;
	pgd_t *pgd, *target_pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	pgd = pgd_offset_pgd(pgdp, addr);
	if (pgd_none(*pgd))
		return NULL;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d))
		return NULL;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return NULL;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return NULL;

	target_pgd = pgd_offset_pgd(target_pgdp, addr);

	if (pmd_large(*pmd)) {
		pgprot_t flags;
		unsigned long pfn;

		/*
		 * We map only PAGE_SIZE rather than the entire huge page.
		 * The PTE will have the same pgprot bits as the origial PMD
		 */
		flags = pte_pgprot(pte_clrhuge(*(pte_t *)pmd));
		pfn = pmd_pfn(*pmd) + pte_index(addr);
		ptev = pfn_pte(pfn, flags);
	} else {
		pte = pte_offset_kernel(pmd, addr);
		if (pte_none(*pte) || !(pte_flags(*pte) & _PAGE_PRESENT))
			return NULL;

		ptev = *pte;
	}

	target_pte = ass_pagetable_walk_pte(mm, target_pgd, addr);
	if (!target_pte)
		return NULL;

	*target_pte = ptev;

	return target_pte;
}

/*
 * Clone a range keeping the same leaf mappings
 *
 * If the range has holes they are simply skipped
 */
int ass_clone_range(struct mm_struct *mm,
		    pgd_t *pgdp, pgd_t *target_pgdp,
		    unsigned long start, unsigned long end)
{
	unsigned long addr;

	/*
	 * Clone the populated PMDs which cover start to end. These PMD areas
	 * can have holes.
	 */
	for (addr = start; addr < end;) {
		pte_t *pte, *target_pte;
		pgd_t *pgd, *target_pgd;
		pmd_t *pmd, *target_pmd;
		p4d_t *p4d;
		pud_t *pud;

		/* Overflow check */
		if (addr < start)
			break;

		pgd = pgd_offset_pgd(pgdp, addr);
		if (pgd_none(*pgd))
			return 0;

		p4d = p4d_offset(pgd, addr);
		if (p4d_none(*p4d))
			return 0;

		pud = pud_offset(p4d, addr);
		if (pud_none(*pud)) {
			addr += PUD_SIZE;
			continue;
		}

		pmd = pmd_offset(pud, addr);
		if (pmd_none(*pmd)) {
			addr += PMD_SIZE;
			continue;
		}

		target_pgd = pgd_offset_pgd(target_pgdp, addr);

		if (pmd_large(*pmd)) {
			target_pmd = ass_pagetable_walk_pmd(mm, target_pgd,
							    addr);
			if (!target_pmd)
				return -ENOMEM;

			*target_pmd = *pmd;

			addr += PMD_SIZE;
			continue;
		} else {
			pte = pte_offset_kernel(pmd, addr);
			if (pte_none(*pte)) {
				addr += PAGE_SIZE;
				continue;
			}

			target_pte = ass_pagetable_walk_pte(mm, target_pgd,
							    addr);
			if (!target_pte)
				return -ENOMEM;

			*target_pte = *pte;

			addr += PAGE_SIZE;
		}
	}

	return 0;
}

static int ass_free_pte_range(struct mm_struct *mm, pmd_t *pmd)
{
	pte_t *ptep = pte_offset_kernel(pmd, 0);

	pmd_clear(pmd);
	pte_free(mm, virt_to_page(ptep));
	mm_dec_nr_ptes(mm);

	return 0;
}

static int ass_free_pmd_range(struct mm_struct *mm, pud_t *pud)
{
	pmd_t *pmd, *pmdp;
	int i;

	pmdp = pmd_offset(pud, 0);

	for (i = 0, pmd = pmdp; i < PTRS_PER_PMD; i++, pmd++)
		if (!pmd_none(*pmd) && !pmd_large(*pmd))
			ass_free_pte_range(mm, pmd);

	pud_clear(pud);
	pmd_free(mm, pmdp);
	mm_dec_nr_pmds(mm);

	return 0;
}

static int ass_free_pud_range(struct mm_struct *mm, p4d_t *p4d)
{
	pud_t *pud, *pudp;
	int i;

	pudp = pud_offset(p4d, 0);

	for (i = 0, pud = pudp; i < PTRS_PER_PUD; i++, pud++)
		if (!pud_none(*pud))
			ass_free_pmd_range(mm, pud);

	p4d_clear(p4d);
	pud_free(mm, pudp);
	mm_dec_nr_puds(mm);

	return 0;
}

static int ass_free_p4d_range(struct mm_struct *mm, pgd_t *pgd)
{
	p4d_t *p4d, *p4dp;
	int i;

	p4dp = p4d_offset(pgd, 0);

	for (i = 0, p4d = p4dp; i < PTRS_PER_P4D; i++, p4d++)
		if (!p4d_none(*p4d))
			ass_free_pud_range(mm, p4d);

	pgd_clear(pgd);
	p4d_free(mm, p4dp);

	return 0;
}

int ass_free_pagetable(struct task_struct *tsk, pgd_t *ass_pgd)
{
	struct mm_struct *mm = tsk->mm;
	pgd_t *pgd, *pgdp = ass_pgd;

	for (pgd = pgdp + KERNEL_PGD_BOUNDARY; pgd < pgdp + PTRS_PER_PGD; pgd++)
		if (!pgd_none(*pgd))
			ass_free_p4d_range(mm, pgd);


	return 0;
}

extern void kernel_map_pages_pgd(pgd_t *pgd, struct page *page,
				 int numpages, int enable);


struct page_excl {
	struct ns_pgd *owner;
};

static bool page_excl_need(void)
{
	return true;
}

static void page_excl_init(void)
{
}

struct page_ext_operations page_excl_ops = {
	.size = sizeof(struct page_excl),
	.need = page_excl_need,
	.init = page_excl_init,
};

static inline struct page_excl *get_page_excl(struct page_ext *page_ext)
{
	return (void *)page_ext + page_excl_ops.offset;
}

static LIST_HEAD(asses);
static pgd_t ass_pgd_shadow[PTRS_PER_PGD] __page_aligned_bss;

static void dump_pgd(pgd_t *pgdp, const char *name)
{
	int i;

	pr_info("===> %s: %px\n", name, pgdp);
	for (i = 0; i < 512; i++, pgdp++)
		if (pgd_val(*pgdp) != 0)
			pr_info("%d: %lx\n", i, pgd_val(*pgdp));
}

struct ns_pgd *ass_create_ns_pgd(struct mm_struct *mm)
{
	struct ns_pgd *ns_pgd;
	pgd_t *pgd;
	p4d_t *p4d;

	pgd = pgd_offset_pgd(mm->pgd, PAGE_OFFSET);
	p4d = p4d_offset(pgd, PAGE_OFFSET);

	p4d_clear(p4d);
	pgd_clear(pgd);

	ass_clone_range(mm, ass_pgd_shadow, mm->pgd,
			PAGE_OFFSET, PAGE_OFFSET + (max_pfn << PAGE_SHIFT));

	ns_pgd = kzalloc(sizeof(*ns_pgd), GFP_KERNEL);
	if (!ns_pgd)
		return NULL;

	ns_pgd->pgd = mm->pgd;
	INIT_LIST_HEAD(&ns_pgd->l);
	INIT_LIST_HEAD(&ns_pgd->caches);

	/* FIXME: locking */
	list_add_tail(&ns_pgd->l, &asses);

	return ns_pgd;
}

static int ass_init_pgd_shadow(void)
{
	pgd_t *pgd;
	p4d_t *p4d;
	int err;

	pr_info("%s: start: %lx end: %lx\n", __func__, PAGE_OFFSET, PAGE_OFFSET + (max_pfn << PAGE_SHIFT));

	clone_pgd_range(ass_pgd_shadow + KERNEL_PGD_BOUNDARY,
			swapper_pg_dir + KERNEL_PGD_BOUNDARY,
			KERNEL_PGD_PTRS);

	pgd = pgd_offset_pgd(ass_pgd_shadow, PAGE_OFFSET);
	p4d = p4d_offset(pgd, PAGE_OFFSET);

	p4d_clear(p4d);
	pgd_clear(pgd);

	err = ass_clone_range(&init_mm, init_mm.pgd,
			      ass_pgd_shadow, PAGE_OFFSET,
			      PAGE_OFFSET + (max_pfn << PAGE_SHIFT));
	if (err)
		return err;

	dump_pgd(ass_pgd_shadow, "ass shadow");

	return 0;
}
late_initcall(ass_init_pgd_shadow);

static int bad_address(void *p)
{
	unsigned long dummy;

	return probe_kernel_address((unsigned long *)p, dummy);
}

static void dump_pagetable(pgd_t *base, unsigned long address)
{
	pgd_t *pgd = base + pgd_index(address);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (bad_address(pgd))
		goto bad;

	pr_info("PGD %lx ", pgd_val(*pgd));

	if (!pgd_present(*pgd))
		goto out;

	p4d = p4d_offset(pgd, address);
	if (bad_address(p4d))
		goto bad;

	pr_cont("P4D %lx ", p4d_val(*p4d));
	if (!p4d_present(*p4d) || p4d_large(*p4d))
		goto out;

	pud = pud_offset(p4d, address);
	if (bad_address(pud))
		goto bad;

	pr_cont("PUD %lx ", pud_val(*pud));
	if (!pud_present(*pud) || pud_large(*pud))
		goto out;

	pmd = pmd_offset(pud, address);
	if (bad_address(pmd))
		goto bad;

	pr_cont("PMD %lx ", pmd_val(*pmd));
	if (!pmd_present(*pmd) || pmd_large(*pmd))
		goto out;

	pte = pte_offset_kernel(pmd, address);
	if (bad_address(pte))
		goto bad;

	pr_cont("PTE %lx", pte_val(*pte));
out:
	pr_cont("\n");
	return;
bad:
	pr_info("BAD\n");
}

int ass_make_page_exclusive(struct page *page, unsigned int order)
{
	struct mm_struct *mm;
	struct ns_pgd *ns_pgd, *p;
	struct page_ext *page_ext;
	struct page_excl *page_excl;

	pr_info("%s: %px(%px), %d\n", __func__, page, page_address(page), order);

	if (!current->mm || (current->flags & PF_KTHREAD)) {
		pr_info("%s: kthread?\n", __func__);
		return 0;
	}

	mm = current->mm;
	ns_pgd = mm->ns_pgd;

	if (!ns_pgd) {
		pr_info("%s: no ns_pgd\n", __func__);
		return 0;
	}

	page_ext = lookup_page_ext(page);
	page_excl = get_page_excl(page_ext);

	__SetPageExclusive(page);
	page_excl->owner = ns_pgd;

	list_for_each_entry(p, &asses, l) {
		if (p != ns_pgd) {
			pr_info("==> make_EX: unmapping in %px\n", p->pgd);
			kernel_map_pages_pgd(p->pgd, page, (1 << order), 0);
			dump_pagetable(p->pgd, (unsigned long)page_address(page));
		}
	}

	pr_info("---> shadow PGD\n");
	kernel_map_pages_pgd(ass_pgd_shadow, page, (1 << order), 0);
	dump_pagetable(ass_pgd_shadow, (unsigned long)page_address(page));

	pr_info("---> owner PGD\n");
	dump_pagetable(ns_pgd->pgd, (unsigned long)page_address(page));

	return 0;
}

void ass_unmake_page_exclusive(struct page *page, unsigned int order)
{
	struct page_ext *page_ext;
	struct page_excl *page_excl;
	struct ns_pgd *owner, *p;

	page_ext = lookup_page_ext(page);
	page_excl = get_page_excl(page_ext);

	if (!page_excl->owner)
		return;

	owner = page_excl->owner;
	list_for_each_entry(p, &asses, l)
		if (p != owner)
			kernel_map_pages_pgd(p->pgd, page, (1 << order), 1);

	kernel_map_pages_pgd(ass_pgd_shadow, page, (1 << order), 1);

	__ClearPageExclusive(page);
	page_excl->owner = NULL;

	return;
}

extern struct kmem_cache *slab_create_cache(const char *name,
		unsigned int object_size, unsigned int align,
		slab_flags_t flags, unsigned int useroffset,
		unsigned int usersize, void (*ctor)(void *),
		struct mem_cgroup *memcg, struct kmem_cache *root_cache);

static struct kmem_cache *ass_kmem_create_cache(struct ns_pgd *ns_pgd,
						struct kmem_cache *cachep)
{
	struct kmem_cache *new = NULL;
	struct ass_kmem_cache *ns_cache;
	char *cache_name;

	pr_info("%s: PGD: %px, cache: %s\n", __func__, ns_pgd->pgd, cachep->name);

	get_online_cpus();
	get_online_mems();

	mutex_lock(&slab_mutex);

	cache_name = kasprintf(GFP_KERNEL, "%s(%px)", cachep->name,
			       ns_pgd->pgd);
	if (!cache_name)
		goto out_unlock;

	ns_cache = kzalloc(sizeof(*ns_cache), GFP_KERNEL);
	if (!ns_cache)
		goto out_free_name;

	new = slab_create_cache(cache_name, cachep->object_size,
				cachep->align,
				cachep->flags & CACHE_CREATE_MASK,
				cachep->useroffset, cachep->usersize,
				cachep->ctor, NULL, NULL);
	if (IS_ERR(new)) {
		new = NULL;
		goto out_free_ns_cache;
	}

	INIT_LIST_HEAD(&ns_cache->l);
	ns_cache->normal = cachep;
	ns_cache->exclusive = new;
	list_add_tail(&ns_cache->l, &ns_pgd->caches);

	goto out_unlock;

out_free_ns_cache:
	kfree(ns_cache);
out_free_name:
	kfree_const(cache_name);

out_unlock:
	mutex_unlock(&slab_mutex);

	put_online_mems();
	put_online_cpus();

	return new;
}

static struct kmem_cache *ass_find_ns_cache(struct ns_pgd *ns_pgd,
					    struct kmem_cache *normal)
{
	struct ass_kmem_cache *c;

	/* FIXME: locking */
	list_for_each_entry(c, &ns_pgd->caches, l)
		if (c->normal == normal)
			return c->exclusive;

	return NULL;
}

struct kmem_cache *ass_kmem_get_cache(struct kmem_cache *cachep)
{
	struct mm_struct *mm;
	struct ns_pgd *ns_pgd;
	struct kmem_cache *new;

	if (!current->mm || (current->flags & PF_KTHREAD)) {
		pr_info("%s: kthread?\n", __func__);
		return cachep;
	}

	mm = current->mm;
	ns_pgd = mm->ns_pgd;

	if (!ns_pgd) {
		pr_info("%s: no ns_pgd\n", __func__);
		return cachep;
	}

	new = ass_find_ns_cache(ns_pgd, cachep);
	if (!new)
		new = ass_kmem_create_cache(ns_pgd, cachep);

	return new;
}

static int ass_pgds_show(struct seq_file *m, void *unused)
{
	struct ns_pgd *ns_pgd;

	list_for_each_entry(ns_pgd, &asses, l)
		seq_printf(m, "%px: %px\n", ns_pgd, ns_pgd->pgd);

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(ass_pgds);

static int ass_debugfs_init(void)
{
	struct dentry *ass_debugfs = debugfs_create_dir("ass", NULL);

	if (!ass_debugfs)
		return -ENOMEM;

	debugfs_create_file("all_pgds", 0400, ass_debugfs, NULL,
			    &ass_pgds_fops);

	return 0;
}
late_initcall(ass_debugfs_init);
