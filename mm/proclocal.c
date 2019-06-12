/*
 * mm/proclocal.c
 *
 * The code in this file implements process-local mappings in the Linux kernel
 * address space. This memory is only usable in the process context. With memory
 * not globally visible in the kernel, it cannot easily be prefetched and leaked
 * via L1TF.
 *
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */
#include <linux/genalloc.h>
#include <linux/mm.h>
#include <linux/proclocal.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include <asm/proclocal.h>
#include <asm/pgalloc.h>
#include <asm/tlb.h>

static pte_t *pte_lookup_map(struct mm_struct *mm, unsigned long kvaddr)
{
	pgd_t *pgd = pgd_offset(mm, kvaddr);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	if (IS_ERR_OR_NULL(pgd) || !pgd_present(*pgd))
		return ERR_PTR(-1);

	p4d = p4d_offset(pgd, kvaddr);
	if (IS_ERR_OR_NULL(p4d) || !p4d_present(*p4d))
		return ERR_PTR(-1);

	pud = pud_offset(p4d, kvaddr);
	if (IS_ERR_OR_NULL(pud) || !pud_present(*pud))
		return ERR_PTR(-1);

	pmd = pmd_offset(pud, kvaddr);
	if (IS_ERR_OR_NULL(pmd) || !pmd_present(*pmd))
		return ERR_PTR(-1);

	return pte_offset_map(pmd, kvaddr);
}

static struct page *proclocal_find_first_page(struct mm_struct *mm, const void *kvaddr)
{
	pte_t *ptep = pte_lookup_map(mm, (unsigned long) kvaddr);

	if(IS_ERR_OR_NULL(ptep))
		return NULL;
	if (!pte_present(*ptep))
		return NULL;

	return pfn_to_page(pte_pfn(*ptep));
}

void proclocal_release_pages(struct list_head *pages)
{
	struct page *pos, *n;
	list_for_each_entry_safe(pos, n, pages, proclocal_next) {
		list_del(&pos->proclocal_next);
		__free_page(pos);
	}
}

static DEFINE_SPINLOCK(proclocal_lock);
static struct gen_pool *allocator;

static int proclocal_allocator_init(void)
{
	int rc;

	allocator = gen_pool_create(PAGE_SHIFT, -1);
	if (unlikely(IS_ERR(allocator)))
		return PTR_ERR(allocator);
	if (!allocator)
		return -1;

	rc = gen_pool_add(allocator, PROCLOCAL_START, PROCLOCAL_SIZE, -1);

	if (rc)
		gen_pool_destroy(allocator);

	return rc;
}
late_initcall(proclocal_allocator_init);

static void *alloc_virtual(size_t nr_pages)
{
	void *kvaddr;
	spin_lock(&proclocal_lock);
	kvaddr = (void *)gen_pool_alloc(allocator, nr_pages * PAGE_SIZE);
	spin_unlock(&proclocal_lock);
	return kvaddr;
}

static void free_virtual(const void *kvaddr, size_t nr_pages)
{
	spin_lock(&proclocal_lock);
	gen_pool_free(allocator, (unsigned long)kvaddr,
			     nr_pages * PAGE_SIZE);
	spin_unlock(&proclocal_lock);
}

void *kmalloc_proclocal(size_t size)
{
	void *kvaddr = NULL;
	size_t nr_pages = round_up(size, PAGE_SIZE) / PAGE_SIZE;
	size_t nr_pages_virtual = nr_pages + 1; /* + guard page */

	BUG_ON(!current);
	if (!size)
		return ZERO_SIZE_PTR;
	might_sleep();

	kvaddr = alloc_virtual(nr_pages_virtual);

	if (IS_ERR_OR_NULL(kvaddr))
		return kvaddr;

	/* tbd: subsequent patch will allocate and map physical pages */

	return kvaddr;
}
EXPORT_SYMBOL(kmalloc_proclocal);

void * kzalloc_proclocal(size_t size)
{
	void * kvaddr = kmalloc_proclocal(size);

	if (!IS_ERR_OR_NULL(kvaddr))
		memset(kvaddr, 0, size);
	return kvaddr;
}
EXPORT_SYMBOL(kzalloc_proclocal);

void kfree_proclocal(void *kvaddr)
{
	struct page *first_page;
	int nr_pages;
	struct mm_struct *mm;

	if (!kvaddr || kvaddr == ZERO_SIZE_PTR)
		return;

	pr_debug("kfree for %p (current %p mm %p)\n", kvaddr,
		 current, current ? current->mm : 0);

	BUG_ON((unsigned long)kvaddr < PROCLOCAL_START);
	BUG_ON((unsigned long)kvaddr >= (PROCLOCAL_START + PROCLOCAL_SIZE));
	BUG_ON(!current);

	mm = current->mm;
	down_write(&mm->mmap_sem);
	first_page = proclocal_find_first_page(mm, kvaddr);
	if (IS_ERR_OR_NULL(first_page)) {
		pr_err("double-free?!\n");
		BUG();
	} /* double-free? */
	nr_pages = first_page->proclocal_nr_pages;
	BUG_ON(!nr_pages);
	mm->proclocal_nr_pages -= nr_pages;
	/* subsequent patch will unmap and release physical pages */
	up_write(&mm->mmap_sem);

	free_virtual(kvaddr, nr_pages + 1);
}
EXPORT_SYMBOL(kfree_proclocal);

void proclocal_mm_exit(struct mm_struct *mm)
{
	pr_debug("proclocal_mm_exit for mm %p pgd %p (current is %p)\n", mm, mm->pgd, current);

	arch_proclocal_teardown_pages_and_pt(mm);
}

void handle_proclocal_page(struct mm_struct *mm, struct page *page,
				  unsigned long addr)
{
	if (page->proclocal_nr_pages) {
		free_virtual((void *)addr, page->proclocal_nr_pages + 1);
	}
}
