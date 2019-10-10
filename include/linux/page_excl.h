/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_PAGE_EXCLUSIVE_H
#define _LINUX_MM_PAGE_EXCLUSIVE_H

#include <linux/bitops.h>
#include <linux/page-flags.h>
#include <linux/set_memory.h>
#include <asm/tlbflush.h>

#ifdef CONFIG_EXCLUSIVE_KERNEL_PAGES

int page_make_exclusive(struct page *page, unsigned int order);
void page_unmake_exclusive(struct page *page, unsigned int order);

#else /* !CONFIG_EXCLUSIVE_KERNEL_PAGES */

static inline int page_make_exclusive(struct page *page, unsigned int order)
{
	return 0;
}

static inline void page_unmake_exclusive(struct page *page, unsigned int order)
{
}

#endif /* CONFIG_EXCLUSIVE_KERNEL_PAGES */

#endif /* _LINUX_MM_PAGE_EXCLUSIVE_H */
