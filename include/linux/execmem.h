/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_EXECMEM_ALLOC_H
#define _LINUX_EXECMEM_ALLOC_H

#include <linux/types.h>

/**
 * execmem_alloc - allocate executable memory
 * @size: how many bytes of memory are required
 *
 * Allocates memory that will contain executable code, either generated or
 * loaded from kernel modules, or data sections for kernel modules
 *
 * Return: a pointer to the allocated memory or %NULL
 */
void *execmem_alloc(size_t size);

/**
 * execmem_free - free executable memory
 * @ptr: pointer to the memory that should be freed
 */
void execmem_free(void *ptr);

#endif /* _LINUX_EXECMEM_ALLOC_H */
