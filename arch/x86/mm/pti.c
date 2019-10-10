// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright(c) 2017 Intel Corporation. All rights reserved.
 *
 * This code is based in part on work published here:
 *
 *	https://github.com/IAIK/KAISER
 *
 * The original work was written by and and signed off by for the Linux
 * kernel by:
 *
 *   Signed-off-by: Richard Fellner <richard.fellner@student.tugraz.at>
 *   Signed-off-by: Moritz Lipp <moritz.lipp@iaik.tugraz.at>
 *   Signed-off-by: Daniel Gruss <daniel.gruss@iaik.tugraz.at>
 *   Signed-off-by: Michael Schwarz <michael.schwarz@iaik.tugraz.at>
 *
 * Major changes to the original code by: Dave Hansen <dave.hansen@intel.com>
 * Mostly rewritten by Thomas Gleixner <tglx@linutronix.de> and
 *		       Andy Lutomirsky <luto@amacapital.net>
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/cpu.h>
#include <linux/asi.h>

#include <asm/cpufeature.h>
#include <asm/hypervisor.h>
#include <asm/vsyscall.h>
#include <asm/cmdline.h>
#include <asm/pti.h>
#include <asm/tlbflush.h>
#include <asm/desc.h>
#include <asm/sections.h>
#include <asm/set_memory.h>

#undef pr_fmt
#define pr_fmt(fmt)     "Kernel/User page tables isolation: " fmt

/* Backporting helper */
#ifndef __GFP_NOTRACK
#define __GFP_NOTRACK	0
#endif

/*
 * Define the page-table levels we clone for user-space on 32
 * and 64 bit.
 */
#ifdef CONFIG_X86_64
#define	PTI_LEVEL_KERNEL_IMAGE	ASI_LEVEL_PMD
#else
#define	PTI_LEVEL_KERNEL_IMAGE	ASI_LEVEL_PTE
#endif

static void __init pti_print_if_insecure(const char *reason)
{
	if (boot_cpu_has_bug(X86_BUG_CPU_MELTDOWN))
		pr_info("%s\n", reason);
}

static void __init pti_print_if_secure(const char *reason)
{
	if (!boot_cpu_has_bug(X86_BUG_CPU_MELTDOWN))
		pr_info("%s\n", reason);
}

static enum pti_mode {
	PTI_AUTO = 0,
	PTI_FORCE_OFF,
	PTI_FORCE_ON
} pti_mode;

void __init pti_check_boottime_disable(void)
{
	char arg[5];
	int ret;

	/* Assume mode is auto unless overridden. */
	pti_mode = PTI_AUTO;

	if (hypervisor_is_type(X86_HYPER_XEN_PV)) {
		pti_mode = PTI_FORCE_OFF;
		pti_print_if_insecure("disabled on XEN PV.");
		return;
	}

	ret = cmdline_find_option(boot_command_line, "pti", arg, sizeof(arg));
	if (ret > 0)  {
		if (ret == 3 && !strncmp(arg, "off", 3)) {
			pti_mode = PTI_FORCE_OFF;
			pti_print_if_insecure("disabled on command line.");
			return;
		}
		if (ret == 2 && !strncmp(arg, "on", 2)) {
			pti_mode = PTI_FORCE_ON;
			pti_print_if_secure("force enabled on command line.");
			goto enable;
		}
		if (ret == 4 && !strncmp(arg, "auto", 4)) {
			pti_mode = PTI_AUTO;
			goto autosel;
		}
	}

	if (cmdline_find_option_bool(boot_command_line, "nopti") ||
	    cpu_mitigations_off()) {
		pti_mode = PTI_FORCE_OFF;
		pti_print_if_insecure("disabled on command line.");
		return;
	}

autosel:
	if (!boot_cpu_has_bug(X86_BUG_CPU_MELTDOWN))
		return;
enable:
	setup_force_cpu_cap(X86_FEATURE_PTI);
}

pgd_t __pti_set_user_pgtbl(pgd_t *pgdp, pgd_t pgd)
{
	/*
	 * Changes to the high (kernel) portion of the kernelmode page
	 * tables are not automatically propagated to the usermode tables.
	 *
	 * Users should keep in mind that, unlike the kernelmode tables,
	 * there is no vmalloc_fault equivalent for the usermode tables.
	 * Top-level entries added to init_mm's usermode pgd after boot
	 * will not be automatically propagated to other mms.
	 */
	if (!pgdp_maps_userspace(pgdp))
		return pgd;

	/*
	 * The user page tables get the full PGD, accessible from
	 * userspace:
	 */
	kernel_to_user_pgdp(pgdp)->pgd = pgd.pgd;

	/*
	 * If this is normal user memory, make it NX in the kernel
	 * pagetables so that, if we somehow screw up and return to
	 * usermode with the kernel CR3 loaded, we'll get a page fault
	 * instead of allowing user code to execute with the wrong CR3.
	 *
	 * As exceptions, we don't set NX if:
	 *  - _PAGE_USER is not set.  This could be an executable
	 *     EFI runtime mapping or something similar, and the kernel
	 *     may execute from it
	 *  - we don't have NX support
	 *  - we're clearing the PGD (i.e. the new pgd is not present).
	 */
	if ((pgd.pgd & (_PAGE_USER|_PAGE_PRESENT)) == (_PAGE_USER|_PAGE_PRESENT) &&
	    (__supported_pte_mask & _PAGE_NX))
		pgd.pgd |= _PAGE_NX;

	/* return the copy of the PGD we want the kernel to use: */
	return pgd;
}

#ifdef CONFIG_X86_VSYSCALL_EMULATION
static void __init pti_setup_vsyscall(void)
{
	unsigned int level;
	pte_t *pte;
	int err;

	pte = lookup_address(VSYSCALL_ADDR, &level);
	if (!pte || WARN_ON(level != PG_LEVEL_4K) || pte_none(*pte))
		return;

	err = asi_map_page(&init_mm, kernel_to_user_pgdp(init_mm.pgd),
			   VSYSCALL_ADDR, PFN_PHYS(pte_pfn(*pte)),
			   __pgprot(pte_flags(*pte)));
	if (WARN_ON(err))
		return;

	set_vsyscall_pgtable_user_bits(kernel_to_user_pgdp(swapper_pg_dir));
}
#else
static void __init pti_setup_vsyscall(void) { }
#endif

enum pti_clone_level {
	PTI_CLONE_PMD,
	PTI_CLONE_PTE,
};

static void
pti_clone_pgtable(unsigned long start, unsigned long end,
		  enum asi_clone_level level)
{
	int err;

	err = asi_clone_pgd_range(&init_mm, &init_mm,
				  kernel_to_user_pgdp(init_mm.pgd),
				  init_mm.pgd,
				  start, end, level);
	WARN_ON(err);
}

#ifdef CONFIG_X86_64
/*
 * Clone a single p4d (i.e. a top-level entry on 4-level systems and a
 * next-level entry on 5-level systems.
 */
static void __init pti_clone_p4d(unsigned long addr)
{
	int err;

	err = asi_clone_pgd_range(&init_mm, &init_mm,
				  kernel_to_user_pgdp(init_mm.pgd),
				  init_mm.pgd, addr, addr + 1,
				  ASI_LEVEL_P4D);
	BUG_ON(err);
}

/*
 * Clone the CPU_ENTRY_AREA and associated data into the user space visible
 * page table.
 */
static void __init pti_clone_user_shared(void)
{
	unsigned int cpu;

	pti_clone_p4d(CPU_ENTRY_AREA_BASE);

	for_each_possible_cpu(cpu) {
		/*
		 * The SYSCALL64 entry code needs to be able to find the
		 * thread stack and needs one word of scratch space in which
		 * to spill a register.  All of this lives in the TSS, in
		 * the sp1 and sp2 slots.
		 *
		 * This is done for all possible CPUs during boot to ensure
		 * that it's propagated to all mms.
		 */

		unsigned long va = (unsigned long)&per_cpu(cpu_tss_rw, cpu);
		phys_addr_t pa = per_cpu_ptr_to_phys((void *)va);
		int err;

		err = asi_map_page(&init_mm, kernel_to_user_pgdp(init_mm.pgd),
				   va, pa, PAGE_KERNEL);
		if (WARN_ON(err))
			return;
	}
}

#else /* CONFIG_X86_64 */

/*
 * On 32 bit PAE systems with 1GB of Kernel address space there is only
 * one pgd/p4d for the whole kernel. Cloning that would map the whole
 * address space into the user page-tables, making PTI useless. So clone
 * the page-table on the PMD level to prevent that.
 */
static void __init pti_clone_user_shared(void)
{
	unsigned long start, end;

	start = CPU_ENTRY_AREA_BASE;
	end   = start + (PAGE_SIZE * CPU_ENTRY_AREA_PAGES);

	pti_clone_pgtable(start, end, ASI_LEVEL_PMD);
}
#endif /* CONFIG_X86_64 */

/*
 * Clone the ESPFIX P4D into the user space visible page table
 */
static void __init pti_setup_espfix64(void)
{
#ifdef CONFIG_X86_ESPFIX64
	pti_clone_p4d(ESPFIX_BASE_ADDR);
#endif
}

/*
 * Clone the populated PMDs of the entry text and force it RO.
 */
static void pti_clone_entry_text(void)
{
	pti_clone_pgtable((unsigned long) __entry_text_start,
			  (unsigned long) __entry_text_end,
			  ASI_LEVEL_PMD);
}

/*
 * Global pages and PCIDs are both ways to make kernel TLB entries
 * live longer, reduce TLB misses and improve kernel performance.
 * But, leaving all kernel text Global makes it potentially accessible
 * to Meltdown-style attacks which make it trivial to find gadgets or
 * defeat KASLR.
 *
 * Only use global pages when it is really worth it.
 */
static inline bool pti_kernel_image_global_ok(void)
{
	/*
	 * Systems with PCIDs get litlle benefit from global
	 * kernel text and are not worth the downsides.
	 */
	if (cpu_feature_enabled(X86_FEATURE_PCID))
		return false;

	/*
	 * Only do global kernel image for pti=auto.  Do the most
	 * secure thing (not global) if pti=on specified.
	 */
	if (pti_mode != PTI_AUTO)
		return false;

	/*
	 * K8 may not tolerate the cleared _PAGE_RW on the userspace
	 * global kernel image pages.  Do the safe thing (disable
	 * global kernel image).  This is unlikely to ever be
	 * noticed because PTI is disabled by default on AMD CPUs.
	 */
	if (boot_cpu_has(X86_FEATURE_K8))
		return false;

	/*
	 * RANDSTRUCT derives its hardening benefits from the
	 * attacker's lack of knowledge about the layout of kernel
	 * data structures.  Keep the kernel image non-global in
	 * cases where RANDSTRUCT is in use to help keep the layout a
	 * secret.
	 */
	if (IS_ENABLED(CONFIG_GCC_PLUGIN_RANDSTRUCT))
		return false;

	return true;
}

/*
 * For some configurations, map all of kernel text into the user page
 * tables.  This reduces TLB misses, especially on non-PCID systems.
 */
static void pti_clone_kernel_text(void)
{
	/*
	 * rodata is part of the kernel image and is normally
	 * readable on the filesystem or on the web.  But, do not
	 * clone the areas past rodata, they might contain secrets.
	 */
	unsigned long start = PFN_ALIGN(_text);
	unsigned long end_clone  = (unsigned long)__end_rodata_aligned;
	unsigned long end_global = PFN_ALIGN((unsigned long)_etext);

	if (!pti_kernel_image_global_ok())
		return;

	pr_debug("mapping partial kernel image into user address space\n");

	/*
	 * Note that this will undo _some_ of the work that
	 * pti_set_kernel_image_nonglobal() did to clear the
	 * global bit.
	 */
	pti_clone_pgtable(start, end_clone, PTI_LEVEL_KERNEL_IMAGE);

	/*
	 * pti_clone_pgtable() will set the global bit in any PMDs
	 * that it clones, but we also need to get any PTEs in
	 * the last level for areas that are not huge-page-aligned.
	 */

	/* Set the global bit for normal non-__init kernel text: */
	set_memory_global(start, (end_global - start) >> PAGE_SHIFT);
}

static void pti_set_kernel_image_nonglobal(void)
{
	/*
	 * The identity map is created with PMDs, regardless of the
	 * actual length of the kernel.  We need to clear
	 * _PAGE_GLOBAL up to a PMD boundary, not just to the end
	 * of the image.
	 */
	unsigned long start = PFN_ALIGN(_text);
	unsigned long end = ALIGN((unsigned long)_end, PMD_PAGE_SIZE);

	/*
	 * This clears _PAGE_GLOBAL from the entire kernel image.
	 * pti_clone_kernel_text() map put _PAGE_GLOBAL back for
	 * areas that are mapped to userspace.
	 */
	set_memory_nonglobal(start, (end - start) >> PAGE_SHIFT);
}

/*
 * Initialize kernel page table isolation
 */
void __init pti_init(void)
{
	if (!boot_cpu_has(X86_FEATURE_PTI))
		return;

	pr_info("enabled\n");

#ifdef CONFIG_X86_32
	/*
	 * We check for X86_FEATURE_PCID here. But the init-code will
	 * clear the feature flag on 32 bit because the feature is not
	 * supported on 32 bit anyway. To print the warning we need to
	 * check with cpuid directly again.
	 */
	if (cpuid_ecx(0x1) & BIT(17)) {
		/* Use printk to work around pr_fmt() */
		printk(KERN_WARNING "\n");
		printk(KERN_WARNING "************************************************************\n");
		printk(KERN_WARNING "** WARNING! WARNING! WARNING! WARNING! WARNING! WARNING!  **\n");
		printk(KERN_WARNING "**                                                        **\n");
		printk(KERN_WARNING "** You are using 32-bit PTI on a 64-bit PCID-capable CPU. **\n");
		printk(KERN_WARNING "** Your performance will increase dramatically if you     **\n");
		printk(KERN_WARNING "** switch to a 64-bit kernel!                             **\n");
		printk(KERN_WARNING "**                                                        **\n");
		printk(KERN_WARNING "** WARNING! WARNING! WARNING! WARNING! WARNING! WARNING!  **\n");
		printk(KERN_WARNING "************************************************************\n");
	}
#endif

	pti_clone_user_shared();

	/* Undo all global bits from the init pagetables in head_64.S: */
	pti_set_kernel_image_nonglobal();
	/* Replace some of the global bits just for shared entry text: */
	pti_clone_entry_text();
	pti_setup_espfix64();
	pti_setup_vsyscall();
}

/*
 * Finalize the kernel mappings in the userspace page-table. Some of the
 * mappings for the kernel image might have changed since pti_init()
 * cloned them. This is because parts of the kernel image have been
 * mapped RO and/or NX.  These changes need to be cloned again to the
 * userspace page-table.
 */
void pti_finalize(void)
{
	if (!boot_cpu_has(X86_FEATURE_PTI))
		return;
	/*
	 * We need to clone everything (again) that maps parts of the
	 * kernel image.
	 */
	pti_clone_entry_text();
	pti_clone_kernel_text();

	debug_checkwx_user();
}
