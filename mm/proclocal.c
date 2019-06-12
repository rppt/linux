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
#include <linux/mm.h>
#include <linux/proclocal.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include <asm/proclocal.h>
#include <asm/pgalloc.h>
#include <asm/tlb.h>

void proclocal_release_pages(struct list_head *pages)
{
	struct page *pos, *n;
	list_for_each_entry_safe(pos, n, pages, proclocal_next) {
		list_del(&pos->proclocal_next);
		__free_page(pos);
	}
}

void proclocal_mm_exit(struct mm_struct *mm)
{
	pr_debug("proclocal_mm_exit for mm %p pgd %p (current is %p)\n", mm, mm->pgd, current);

	arch_proclocal_teardown_pages_and_pt(mm);
}
