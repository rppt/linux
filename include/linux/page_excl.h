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

/* FIXME: add support for kernel exclusive pages for 32-bits using page_ext */

static inline bool page_is_exclusive(struct page *page)
{
	return PageExclusive(page);
}

static inline void __set_page_exclusive(struct page *page)
{
	__SetPageExclusive(page);
}

static inline void __clear_page_exclusive(struct page *page)
{
	__ClearPageExclusive(page);
}

#else /* !CONFIG_EXCLUSIVE_KERNEL_PAGES */

static inline bool page_is_exclusive(struct page *page)
{
	return false;
}

static inline void __set_page_exclusive(struct page *page)
{
}

static inline void __clear_page_exclusive(struct page *page)
{
}

static inline int page_make_exclusive(struct page *page, unsigned int order)
{
	return 0;
}

static inline void page_unmake_exclusive(struct page *page, unsigned int order)
{
}

#endif /* CONFIG_EXCLUSIVE_KERNEL_PAGES */

#endif /* _LINUX_MM_PAGE_EXCLUSIVE_H */
