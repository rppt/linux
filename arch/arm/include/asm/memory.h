/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *  arch/arm/include/asm/memory.h
 *
 *  Copyright (C) 2000-2002 Russell King
 *  modification for nommu, Hyok S. Choi, 2004
 *
 *  Note: this file should not be included by non-asm/.h files
 */
#ifndef __ASM_ARM_MEMORY_H
#define __ASM_ARM_MEMORY_H

#include <linux/compiler.h>
#include <linux/const.h>
#include <linux/types.h>
#include <linux/sizes.h>

#ifdef CONFIG_NEED_MACH_MEMORY_H
#include <mach/memory.h>
#endif
#include <asm/kasan_def.h>

#include <asm/virtconvert.h>

#ifdef CONFIG_MMU

/*
 * TASK_SIZE - the maximum size of a user space task.
 * TASK_UNMAPPED_BASE - the lower boundary of the mmap VM area
 */
#ifndef CONFIG_KASAN
#define TASK_SIZE		(UL(CONFIG_PAGE_OFFSET) - UL(SZ_16M))
#else
#define TASK_SIZE		(KASAN_SHADOW_START)
#endif
#define TASK_UNMAPPED_BASE	ALIGN(TASK_SIZE / 3, SZ_16M)

/*
 * The maximum size of a 26-bit user space task.
 */
#define TASK_SIZE_26		(UL(1) << 26)

/*
 * The module space lives between the addresses given by TASK_SIZE
 * and PAGE_OFFSET - it must be within 32MB of the kernel text.
 */
#ifndef CONFIG_THUMB2_KERNEL
#define MODULES_VADDR		(PAGE_OFFSET - SZ_16M)
#else
/* smaller range for Thumb-2 symbols relocation (2^24)*/
#define MODULES_VADDR		(PAGE_OFFSET - SZ_8M)
#endif

#if TASK_SIZE > MODULES_VADDR
#error Top of user space clashes with start of module space
#endif

/*
 * The highmem pkmap virtual space shares the end of the module area.
 */
#ifdef CONFIG_HIGHMEM
#define MODULES_END		(PAGE_OFFSET - PMD_SIZE)
#else
#define MODULES_END		(PAGE_OFFSET)
#endif

/*
 * The XIP kernel gets mapped at the bottom of the module vm area.
 * Since we use sections to map it, this macro replaces the physical address
 * with its virtual address while keeping offset from the base section.
 */
#define XIP_VIRT_ADDR(physaddr)  (MODULES_VADDR + ((physaddr) & 0x000fffff))

#define FDT_FIXED_BASE		UL(0xff800000)
#define FDT_FIXED_SIZE		(2 * SECTION_SIZE)
#define FDT_VIRT_BASE(physbase)	((void *)(FDT_FIXED_BASE | (physbase) % SECTION_SIZE))

#if !defined(CONFIG_SMP) && !defined(CONFIG_ARM_LPAE)
/*
 * Allow 16MB-aligned ioremap pages
 */
#define IOREMAP_MAX_ORDER	24
#endif

#define VECTORS_BASE		UL(0xffff0000)

#else /* CONFIG_MMU */

#ifndef __ASSEMBLY__
extern unsigned long setup_vectors_base(void);
extern unsigned long vectors_base;
#define VECTORS_BASE		vectors_base
#endif

/*
 * The limitation of user task size can grow up to the end of free ram region.
 * It is difficult to define and perhaps will never meet the original meaning
 * of this define that was meant to.
 * Fortunately, there is no reference for this in noMMU mode, for now.
 */
#define TASK_SIZE		UL(0xffffffff)

#ifndef TASK_UNMAPPED_BASE
#define TASK_UNMAPPED_BASE	UL(0x00000000)
#endif

#ifndef END_MEM
#define END_MEM     		(UL(CONFIG_DRAM_BASE) + CONFIG_DRAM_SIZE)
#endif

/*
 * The module can be at any place in ram in nommu mode.
 */
#define MODULES_END		(END_MEM)
#define MODULES_VADDR		PAGE_OFFSET

#define XIP_VIRT_ADDR(physaddr)  (physaddr)
#define FDT_VIRT_BASE(physbase)  ((void *)(physbase))

#endif /* !CONFIG_MMU */

#ifdef CONFIG_XIP_KERNEL
#define KERNEL_START		_sdata
#else
#define KERNEL_START		_stext
#endif
#define KERNEL_END		_end

/*
 * We fix the TCM memories max 32 KiB ITCM resp DTCM at these
 * locations
 */
#ifdef CONFIG_HAVE_TCM
#define ITCM_OFFSET	UL(0xfffe0000)
#define DTCM_OFFSET	UL(0xfffe8000)
#endif

#ifndef __ASSEMBLY__

/*
 * Physical start and end address of the kernel sections. These addresses are
 * 2MB-aligned to match the section mappings placed over the kernel. We use
 * u64 so that LPAE mappings beyond the 32bit limit will work out as well.
 */
extern u64 kernel_sec_start;
extern u64 kernel_sec_end;

#endif

#define ARCH_PFN_OFFSET		PHYS_PFN_OFFSET
#include <asm-generic/memory_model.h>

#endif
