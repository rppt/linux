/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm/include/asm/memory.h
 * See that file for respective copyrights.
 */
#ifndef __ASM_ARM_VIRTCONVERT_H
#define __ASM_ARM_VIRTCONVERT_H

#include <linux/types.h>

/*
 * PAGE_OFFSET: the virtual address of the start of lowmem, memory above
 *   the virtual address range for userspace.
 * KERNEL_OFFSET: the virtual address of the start of the kernel image.
 *   we may further offset this with TEXT_OFFSET in practice.
 */
#define PAGE_OFFSET		UL(CONFIG_PAGE_OFFSET)
#define KERNEL_OFFSET		(PAGE_OFFSET)

/*
 * Convert a page to/from a physical address
 */
#define page_to_phys(page)	(__pfn_to_phys(page_to_pfn(page)))
#define phys_to_page(phys)	(pfn_to_page(__phys_to_pfn(phys)))

/*
 * PLAT_PHYS_OFFSET is the offset (from zero) of the start of physical
 * memory.  This is used for XIP and NoMMU kernels, and on platforms that don't
 * have CONFIG_ARM_PATCH_PHYS_VIRT. Assembly code must always use
 * PLAT_PHYS_OFFSET and not PHYS_OFFSET.
 */
#define PLAT_PHYS_OFFSET	UL(CONFIG_PHYS_OFFSET)

#ifndef __ASSEMBLY__

/*
 * Physical vs virtual RAM address space conversion.  These are
 * private definitions which should NOT be used outside memory.h
 * files.  Use virt_to_phys/phys_to_virt/__pa/__va instead.
 *
 * PFNs are used to describe any physical page; this means
 * PFN 0 == physical address 0.
 */

#if defined(CONFIG_ARM_PATCH_PHYS_VIRT)

/*
 * Constants used to force the right instruction encodings and shifts
 * so that all we need to do is modify the 8-bit constant field.
 */
#define __PV_BITS_31_24	0x81000000
#define __PV_BITS_23_16	0x810000
#define __PV_BITS_7_0	0x81

extern unsigned long __pv_phys_pfn_offset;
extern u64 __pv_offset;
extern void fixup_pv_table(const void *, unsigned long);
extern const void *__pv_table_begin, *__pv_table_end;

#define PHYS_OFFSET	((phys_addr_t)__pv_phys_pfn_offset << PAGE_SHIFT)
#define PHYS_PFN_OFFSET	(__pv_phys_pfn_offset)

#ifndef CONFIG_THUMB2_KERNEL
#define __pv_stub(from,to,instr)			\
	__asm__("@ __pv_stub\n"				\
	"1:	" instr "	%0, %1, %2\n"		\
	"2:	" instr "	%0, %0, %3\n"		\
	"	.pushsection .pv_table,\"a\"\n"		\
	"	.long	1b - ., 2b - .\n"		\
	"	.popsection\n"				\
	: "=r" (to)					\
	: "r" (from), "I" (__PV_BITS_31_24),		\
	  "I"(__PV_BITS_23_16))

#define __pv_add_carry_stub(x, y)			\
	__asm__("@ __pv_add_carry_stub\n"		\
	"0:	movw	%R0, #0\n"			\
	"	adds	%Q0, %1, %R0, lsl #20\n"	\
	"1:	mov	%R0, %2\n"			\
	"	adc	%R0, %R0, #0\n"			\
	"	.pushsection .pv_table,\"a\"\n"		\
	"	.long	0b - ., 1b - .\n"		\
	"	.popsection\n"				\
	: "=&r" (y)					\
	: "r" (x), "I" (__PV_BITS_7_0)			\
	: "cc")

#else
#define __pv_stub(from,to,instr)			\
	__asm__("@ __pv_stub\n"				\
	"0:	movw	%0, #0\n"			\
	"	lsl	%0, #21\n"			\
	"	" instr " %0, %1, %0\n"			\
	"	.pushsection .pv_table,\"a\"\n"		\
	"	.long	0b - .\n"			\
	"	.popsection\n"				\
	: "=&r" (to)					\
	: "r" (from))

#define __pv_add_carry_stub(x, y)			\
	__asm__("@ __pv_add_carry_stub\n"		\
	"0:	movw	%R0, #0\n"			\
	"	lsls	%R0, #21\n"			\
	"	adds	%Q0, %1, %R0\n"			\
	"1:	mvn	%R0, #0\n"			\
	"	adc	%R0, %R0, #0\n"			\
	"	.pushsection .pv_table,\"a\"\n"		\
	"	.long	0b - ., 1b - .\n"		\
	"	.popsection\n"				\
	: "=&r" (y)					\
	: "r" (x)					\
	: "cc")
#endif

static inline phys_addr_t __virt_to_phys_nodebug(unsigned long x)
{
	phys_addr_t t;

	if (sizeof(phys_addr_t) == 4) {
		__pv_stub(x, t, "add");
	} else {
		__pv_add_carry_stub(x, t);
	}
	return t;
}

static inline unsigned long __phys_to_virt(phys_addr_t x)
{
	unsigned long t;

	/*
	 * 'unsigned long' cast discard upper word when
	 * phys_addr_t is 64 bit, and makes sure that inline
	 * assembler expression receives 32 bit argument
	 * in place where 'r' 32 bit operand is expected.
	 */
	__pv_stub((unsigned long) x, t, "sub");
	return t;
}

#else

#define PHYS_OFFSET	PLAT_PHYS_OFFSET
#define PHYS_PFN_OFFSET	((unsigned long)(PHYS_OFFSET >> PAGE_SHIFT))

static inline phys_addr_t __virt_to_phys_nodebug(unsigned long x)
{
	return (phys_addr_t)x - PAGE_OFFSET + PHYS_OFFSET;
}

static inline unsigned long __phys_to_virt(phys_addr_t x)
{
	return x - PHYS_OFFSET + PAGE_OFFSET;
}

#endif

#define virt_to_pfn(kaddr) \
	((((unsigned long)(kaddr) - PAGE_OFFSET) >> PAGE_SHIFT) + \
	 PHYS_PFN_OFFSET)

#define __pa_symbol_nodebug(x)	__virt_to_phys_nodebug((x))

#ifdef CONFIG_DEBUG_VIRTUAL
extern phys_addr_t __virt_to_phys(unsigned long x);
extern phys_addr_t __phys_addr_symbol(unsigned long x);
#else
#define __virt_to_phys(x)	__virt_to_phys_nodebug(x)
#define __phys_addr_symbol(x)	__pa_symbol_nodebug(x)
#endif

/*
 * These are *only* valid on the kernel direct mapped RAM memory.
 * Note: Drivers should NOT use these.  They are the wrong
 * translation for translating DMA addresses.  Use the driver
 * DMA support - see dma-mapping.h.
 */
#define virt_to_phys virt_to_phys
static inline phys_addr_t virt_to_phys(const volatile void *x)
{
	return __virt_to_phys((unsigned long)(x));
}

#define phys_to_virt phys_to_virt
static inline void *phys_to_virt(phys_addr_t x)
{
	return (void *)__phys_to_virt(x);
}

/*
 * Drivers should NOT use these either.
 */
#define __pa(x)			__virt_to_phys((unsigned long)(x))
#define __pa_symbol(x)		__phys_addr_symbol(RELOC_HIDE((unsigned long)(x), 0))
#define __va(x)			((void *)__phys_to_virt((phys_addr_t)(x)))
#define pfn_to_kaddr(pfn)	__va((phys_addr_t)(pfn) << PAGE_SHIFT)

extern long long arch_phys_to_idmap_offset;

/*
 * These are for systems that have a hardware interconnect supported alias
 * of physical memory for idmap purposes.  Most cases should leave these
 * untouched.  Note: this can only return addresses less than 4GiB.
 */
static inline bool arm_has_idmap_alias(void)
{
	return IS_ENABLED(CONFIG_MMU) && arch_phys_to_idmap_offset != 0;
}

#define IDMAP_INVALID_ADDR ((u32)~0)

static inline unsigned long phys_to_idmap(phys_addr_t addr)
{
	if (IS_ENABLED(CONFIG_MMU) && arch_phys_to_idmap_offset) {
		addr += arch_phys_to_idmap_offset;
		if (addr > (u32)~0)
			addr = IDMAP_INVALID_ADDR;
	}
	return addr;
}

static inline phys_addr_t idmap_to_phys(unsigned long idmap)
{
	phys_addr_t addr = idmap;

	if (IS_ENABLED(CONFIG_MMU) && arch_phys_to_idmap_offset)
		addr -= arch_phys_to_idmap_offset;

	return addr;
}

static inline unsigned long __virt_to_idmap(unsigned long x)
{
	return phys_to_idmap(__virt_to_phys(x));
}

#define virt_to_idmap(x)	__virt_to_idmap((unsigned long)(x))

/*
 * Virtual <-> DMA view memory address translations
 * Again, these are *only* valid on the kernel direct mapped RAM
 * memory.  Use of these is *deprecated* (and that doesn't mean
 * use the __ prefixed forms instead.)  See dma-mapping.h.
 */
#ifndef __virt_to_bus
#define __virt_to_bus	__virt_to_phys
#define __bus_to_virt	__phys_to_virt
#define __pfn_to_bus(x)	__pfn_to_phys(x)
#define __bus_to_pfn(x)	__phys_to_pfn(x)
#endif

/*
 * Conversion between a struct page and a physical address.
 *
 *  page_to_pfn(page)	convert a struct page * to a PFN number
 *  pfn_to_page(pfn)	convert a _valid_ PFN number to struct page *
 *
 *  virt_to_page(k)	convert a _valid_ virtual address to struct page *
 *  virt_addr_valid(k)	indicates whether a virtual address is valid
 */

#define virt_to_page(kaddr)	pfn_to_page(virt_to_pfn(kaddr))
#define virt_addr_valid(kaddr)	(((unsigned long)(kaddr) >= PAGE_OFFSET && (unsigned long)(kaddr) < (unsigned long)high_memory) \
					&& pfn_valid(virt_to_pfn(kaddr)))

#endif

#endif
