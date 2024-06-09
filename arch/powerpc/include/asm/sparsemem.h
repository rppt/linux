/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_POWERPC_SPARSEMEM_H
#define _ASM_POWERPC_SPARSEMEM_H 1
#ifdef __KERNEL__

#ifdef CONFIG_SPARSEMEM
/*
 * SECTION_SIZE_BITS		2^N: how big each section will be
 * MAX_PHYSMEM_BITS		2^N: how much memory we can have in that space
 */
#define SECTION_SIZE_BITS       24

#endif /* CONFIG_SPARSEMEM */

#endif /* __KERNEL__ */
#endif /* _ASM_POWERPC_SPARSEMEM_H */
