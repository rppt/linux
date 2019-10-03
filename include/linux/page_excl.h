/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_PAGE_EXCLUSIVE_H
#define _LINUX_MM_PAGE_EXCLUSIVE_H

#include <linux/bitops.h>
#include <linux/page-flags.h>
#include <linux/set_memory.h>
#include <asm/tlbflush.h>

#ifdef CONFIG_EXCLUSIVE_USER_PAGES

static inline bool page_is_user_exclusive(struct page *page)
{
	return PageUserExclusive(page);
}

static inline void __set_page_user_exclusive(struct page *page)
{
	unsigned long addr = (unsigned long)page_address(page);

	__SetPageUserExclusive(page);
	set_direct_map_invalid_noflush(page);
	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
}

static inline void __clear_page_user_exclusive(struct page *page)
{
	__ClearPageUserExclusive(page);
	set_direct_map_default_noflush(page);
}

#else /* !CONFIG_EXCLUSIVE_USER_PAGES */

static inline bool page_is_user_exclusive(struct page *page)
{
	return false;
}

static inline void __set_page_user_exclusive(struct page *page)
{
}

static inline void __clear_page_user_exclusive(struct page *page)
{
}

#endif /* CONFIG_EXCLUSIVE_USER_PAGES */

#endif /* _LINUX_MM_PAGE_EXCLUSIVE_H */
