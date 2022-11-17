/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __UNMAPPED_ALLOC_H
#define __UNMAPPED_ALLOC_H

#include <linux/types.h>

int unmapped_alloc_init(void);

struct page;

struct page *unmapped_pages_alloc(int order);
void unmapped_pages_free(struct page *page, int order);

static inline struct page *unmapped_page_alloc(void)
{
	return unmapped_pages_alloc(0);
}

static inline void unmapped_page_free(struct page *page)
{
	return unmapped_pages_free(page, 0);
}

#endif /* __UNMAPPED_ALLOC_H */
