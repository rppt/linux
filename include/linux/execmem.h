/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_EXECMEM_ALLOC_H
#define _LINUX_EXECMEM_ALLOC_H

#include <linux/types.h>

/**
 * struct execmem_range - definition of a memory range suitable for code and
 *			  related data allocations
 * @start:	address space start
 * @end:	address space end (inclusive)
 * @pgprot:	permisssions for memory in this address space
 * @alignment:	alignment required for text allocations
 */
struct execmem_range {
	unsigned long   start;
	unsigned long   end;
	pgprot_t        pgprot;
	unsigned int	alignment;
};

/**
 * struct execmem_modules_range - architecure parameters for modules address
 *				  space
 * @text:	address range for text allocations
 */
struct execmem_modules_range {
	struct execmem_range text;
};

/**
 * struct execmem_params -	architecure parameters for code allocations
 * @modules:	parameters for modules address space
 */
struct execmem_params {
	struct execmem_modules_range	modules;
};

struct execmem_params *execmem_arch_params(void);

void *execmem_text_alloc(size_t size);
void execmem_free(void *ptr);

#ifdef CONFIG_EXECMEM
void execmem_init(void);
#else
static inline void execmem_init(void) {}
#endif

#endif /* _LINUX_EXECMEM_ALLOC_H */
