/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PAGEATTR_H
#define _ASM_X86_PAGEATTR_H

#include <linux/spinlock.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/sections.h>

struct cpa_data;

#ifdef CONFIG_X86_64
/*
 * The kernel image is mapped into two places in the virtual address space
 * (addresses without KASLR, of course):
 *
 * 1. The kernel direct map (0xffff880000000000)
 * 2. The "high kernel map" (0xffffffff81000000)
 *
 * We actually execute out of #2. If we get the address of a kernel symbol, it
 * points to #2, but almost all physical-to-virtual translations point to #1.
 *
 * This is so that we can have both a directmap of all physical memory *and*
 * take full advantage of the limited (s32) immediate addressing range (2G)
 * of x86_64.
 *
 * See Documentation/arch/x86/x86_64/mm.rst for more detail.
 */
static inline unsigned long highmap_start_pfn(void)
{
	return __pa_symbol(_text) >> PAGE_SHIFT;
}

static inline unsigned long highmap_end_pfn(void)
{
	/* Do not reference physical address outside the kernel. */
	return __pa_symbol(roundup(_brk_end, PMD_SIZE) - 1) >> PAGE_SHIFT;
}

static inline bool __cpa_pfn_in_highmap(unsigned long pfn)
{
	/*
	 * Kernel text has an alias mapping at a high address, known
	 * here as "highmap".
	 */
	return pfn >= highmap_start_pfn() && pfn <= highmap_end_pfn();
}
#else
static inline bool __cpa_pfn_in_highmap(unsigned long pfn)
{
	/* There is no highmap on 32-bit */
	return false;
}
#endif

/*
 * The direct map aliases all of physical memory, and on 64-bit the kernel
 * text is aliased by the high mapping.  A change to one alias has to be
 * applied to the others.
 *
 * Keep this inline: it runs once per page and says no most of the time.
 */
static inline bool arch_cpa_needs_alias(unsigned long vaddr, unsigned long pfn)
{
	unsigned long dmap_end = PAGE_OFFSET + (max_pfn_mapped << PAGE_SHIFT);

	if (!pfn_range_is_mapped(pfn, pfn + 1))
		return false;

	if (vaddr < PAGE_OFFSET || vaddr >= dmap_end)
		return true;

	return !(vaddr >= (unsigned long)_text && vaddr < _brk_end) &&
	       __cpa_pfn_in_highmap(pfn);
}

/*
 * CPA walks the kernel page tables, so it has to serialize against everything
 * else that does, not just against other CPA calls.
 */
static inline void arch_cpa_pgtable_lock(void)
{
	spin_lock(&pgd_lock);
}

static inline void arch_cpa_pgtable_unlock(void)
{
	spin_unlock(&pgd_lock);
}

int arch_cpa_process_alias(struct cpa_data *cpa);
void arch_cpa_flush(struct cpa_data *cpa);
int arch_cpa_collapse(unsigned long addr, struct list_head *pgtables);

#endif /* _ASM_X86_PAGEATTR_H */
