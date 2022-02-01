/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef __ASM_GENERIC_VIRTCONVERT_H
#define __ASM_GENERIC_VIRTCONVERT_H

#ifndef __ASSEMBLY__

#ifndef __va
#define __va(x) ((void *)((unsigned long) (x)))
#endif

#ifndef __pa
#define __pa(x) ((unsigned long) (x))
#endif

/*
 * Change virtual addresses to physical addresses and vv.
 * These are pretty trivial
 */
#ifndef virt_to_phys
#define virt_to_phys virt_to_phys
static inline unsigned long virt_to_phys(volatile void *address)
{
	return __pa((unsigned long)address);
}
#endif

#ifndef phys_to_virt
#define phys_to_virt phys_to_virt
static inline void *phys_to_virt(unsigned long address)
{
	return __va(address);
}
#endif

#endif /* __ASSEMBLY__ */

#endif /*__ASM_GENERIC_VIRTCONVERT_H */
