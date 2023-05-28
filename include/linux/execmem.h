/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_EXECMEM_ALLOC_H
#define _LINUX_EXECMEM_ALLOC_H

#include <linux/types.h>

void *execmem_text_alloc(size_t size);
void execmem_free(void *ptr);

#endif /* _LINUX_EXECMEM_ALLOC_H */
