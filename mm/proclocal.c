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

/*
 * Lookup PTE for a given virtual address. Allocate page table structures, if
 * they are not present yet.
 */
static pte_t *pte_lookup_alloc_map(struct mm_struct *mm, unsigned long kvaddr)
{
	pgd_t *pgd = pgd_offset(mm, kvaddr);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	p4d = p4d_alloc(mm, pgd, kvaddr);
	if (IS_ERR_OR_NULL(p4d))
		return (pte_t *)p4d;

	pud = pud_alloc(mm, p4d, kvaddr);
	if (IS_ERR_OR_NULL(pud))
		return (pte_t *)pud;

	pmd = pmd_alloc(mm, pud, kvaddr);
	if (IS_ERR_OR_NULL(pmd))
		return (pte_t *)pmd;

	return pte_alloc_map(mm, pmd, kvaddr);
}

static int proclocal_map_notlbflush(struct mm_struct *mm, struct page *page, void *kvaddr)
{
	int rc;
	pte_t *ptep = pte_lookup_alloc_map(mm, (unsigned long)kvaddr);

	if (IS_ERR_OR_NULL(ptep)) {
		pr_err("failed to pte_lookup_alloc_map, ptep=0x%lx\n",
		       (unsigned long)ptep);
		return ptep ? PTR_ERR(ptep) : -ENOMEM;
	}

	set_pte(ptep, mk_pte(page, kmap_prot));
	rc = set_direct_map_invalid_noflush(page);
	if (rc)
		pte_clear(mm, (unsigned long)kvaddr, ptep);
	else
		pr_debug("map pfn %lx at %p for mm %p pgd %p\n", page_to_pfn(page), kvaddr, mm, mm->pgd);
	return rc;
}

static void proclocal_unmap_page_notlbflush(struct mm_struct *mm, void *vaddr)
{
	pte_t *ptep = pte_lookup_map(mm, (unsigned long)vaddr);
	pte_t pte;
	struct page *page;

	BUG_ON(IS_ERR_OR_NULL(ptep));
	BUG_ON(!pte_present(*ptep)); // already cleared?!

	/* scrub page contents */
	memset(vaddr, 0, PAGE_SIZE);

	pte = ptep_get_and_clear(mm, (unsigned long)vaddr, ptep);
	page = pfn_to_page(pte_pfn(pte));

	BUG_ON(set_direct_map_default_noflush(page)); /* should never fail for mapped 4K-pages */
}

void proclocal_release_pages(struct list_head *pages)
{
	struct page *pos, *n;
	list_for_each_entry_safe(pos, n, pages, proclocal_next) {
		list_del(&pos->proclocal_next);
		__free_page(pos);
	}
}

static void proclocal_release_pages_incl_head(struct list_head *pages)
{
	proclocal_release_pages(pages);
	/* the list_head itself is embedded in a struct page we want to release. */
	__free_page(list_entry(pages, struct page, proclocal_next));
}

struct physmap_tlb_flush {
	unsigned long start;
	unsigned long end;
};

static inline void track_page_to_flush(struct physmap_tlb_flush *flush, struct page *page)
{
	const unsigned long page_start = (unsigned long)page_to_virt(page);
	const unsigned long page_end = page_start + PAGE_SIZE;

	if (page_start < flush->start)
		flush->start = page_start;
	if (page_end > flush->end)
		flush->end = page_end;
}

static int alloc_and_map_proclocal_pages(struct mm_struct *mm, void *kvaddr, size_t nr_pages)
{
	int rc;
	size_t i, j;
	struct page *page;
	struct list_head *pages_list = NULL;
	struct physmap_tlb_flush flush = { -1, 0 };

	for (i = 0; i < nr_pages; i++) {
		page = alloc_page(GFP_KERNEL);

		if (!page) {
			rc = -ENOMEM;
			goto unmap_release;
		}

		rc = proclocal_map_notlbflush(mm, page, kvaddr + i * PAGE_SIZE);
		if (rc) {
			__free_page(page);
			goto unmap_release;
		}

		track_page_to_flush(&flush, page);
		INIT_LIST_HEAD(&page->proclocal_next);
		/* track allocation in first struct page */
		if (!pages_list) {
			pages_list = &page->proclocal_next;
			page->proclocal_nr_pages = nr_pages;
		} else {
			list_add_tail(&page->proclocal_next, pages_list);
			page->proclocal_nr_pages = 0;
		}
	}

	/* flush direct mappings of allocated pages from TLBs. */
	flush_tlb_kernel_range(flush.start, flush.end);
	return 0;

unmap_release:
	for (j = 0; j < i; j++)
		proclocal_unmap_page_notlbflush(mm, kvaddr + j * PAGE_SIZE);

	if (pages_list)
		proclocal_release_pages_incl_head(pages_list);
	return rc;
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
	int rc;
	void *kvaddr = NULL;
	size_t nr_pages = round_up(size, PAGE_SIZE) / PAGE_SIZE;
	size_t nr_pages_virtual = nr_pages + 1; /* + guard page */
	struct mm_struct *mm;

	BUG_ON(!current);
	if (!size)
		return ZERO_SIZE_PTR;
	might_sleep();

	kvaddr = alloc_virtual(nr_pages_virtual);

	if (IS_ERR_OR_NULL(kvaddr))
		return kvaddr;

	mm = current->mm;
	down_write(&mm->mmap_sem);
	rc = alloc_and_map_proclocal_pages(mm, kvaddr, nr_pages);
	if (!rc)
		mm->proclocal_nr_pages += nr_pages;
	up_write(&mm->mmap_sem);

	if (unlikely(rc))
		kvaddr = ERR_PTR(rc);

	pr_debug("allocated %zd bytes at %p (current %p mm %p)\n", size, kvaddr,
		 current, current ? current->mm : 0);

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
	int i;
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

	might_sleep();
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

	for (i = 0; i < nr_pages; i++)
		proclocal_unmap_page_notlbflush(mm, kvaddr + i * PAGE_SIZE);

	up_write(&mm->mmap_sem);

	/*
	 * Flush process-local mappings from TLBs so that we can release the
	 * pages afterwards.
	 */
	flush_tlb_mm_range(mm, (unsigned long)kvaddr,
			   (unsigned long)kvaddr + nr_pages * PAGE_SIZE,
			   PAGE_SHIFT, false);

	proclocal_release_pages_incl_head(&first_page->proclocal_next);

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
