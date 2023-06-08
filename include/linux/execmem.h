/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_EXECMEM_ALLOC_H
#define _LINUX_EXECMEM_ALLOC_H

#include <linux/types.h>

#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
		!defined(CONFIG_KASAN_VMALLOC)
#include <linux/kasan.h>
#define MODULE_ALIGN (PAGE_SIZE << KASAN_SHADOW_SCALE_SHIFT)
#else
#define MODULE_ALIGN PAGE_SIZE
#endif

/**
 * struct execmem_range - definition of a memory range suitable for code and
 *			  related data allocations
 * @start:	address space start
 * @end:	address space end (inclusive)
 * @fallback_start:	start of the range for fallback allocations
 * @fallback_end:	end of the range for fallback allocations (inclusive)
 * @pgprot:	permisssions for memory in this address space
 * @alignment:	alignment required for text allocations
 */
struct execmem_range {
	unsigned long   start;
	unsigned long   end;
	unsigned long   fallback_start;
	unsigned long   fallback_end;
	pgprot_t        pgprot;
	unsigned int	alignment;
};

/**
 * enum execmem_module_flags - options for executable memory allocations
 * @EXECMEM_KASAN_SHADOW:	allocate kasan shadow
 */
enum execmem_module_flags {
	EXECMEM_KASAN_SHADOW	= (1 << 0),
};

/**
 * struct execmem_modules_range - architecure parameters for modules address
 *				  space
 * @flags:	options for module memory allocations
 * @text:	address range for text allocations
 */
struct execmem_modules_range {
	enum execmem_module_flags flags;
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
