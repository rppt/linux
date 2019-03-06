/*
 * Copyright(c) 2017 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
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
#include <linux/kallsyms.h>

#include <asm/cpufeature.h>
#include <asm/hypervisor.h>
#include <asm/vsyscall.h>
#include <asm/cmdline.h>
#include <asm/pti.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/desc.h>
#include <asm/sections.h>
#include <asm/traps.h>
#include <asm/nospec-branch.h>

#undef pr_fmt
/* #define pr_fmt(fmt)     "Kernel/User page tables isolation: " fmt */
#define pr_fmt(fmt)     "kPTI: " fmt

/* Backporting helper */
#ifndef __GFP_NOTRACK
#define __GFP_NOTRACK	0
#endif

/*
 * Define the page-table levels we clone for user-space on 32
 * and 64 bit.
 */
#ifdef CONFIG_X86_64
#define	PTI_LEVEL_KERNEL_IMAGE	PTI_CLONE_PMD
#else
#define	PTI_LEVEL_KERNEL_IMAGE	PTI_CLONE_PTE
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

enum pti_mode {
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

	if (cmdline_find_option_bool(boot_command_line, "nopti")) {
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

#ifdef CONFIG_INTERNAL_PTI
	kernel_to_entry_pgdp(pgdp)->pgd = pgd.pgd;
#endif

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

/*
 * Walk the user copy of the page tables (optionally) trying to allocate
 * page table pages on the way down.
 *
 * Returns a pointer to a P4D on success, or NULL on failure.
 */
static p4d_t *pti_user_pagetable_walk_p4d(unsigned long address, bool entry)
{
	pgd_t *pgd;
	gfp_t gfp = (GFP_KERNEL | __GFP_NOTRACK | __GFP_ZERO);

	if (!entry)
		pgd = kernel_to_user_pgdp(pgd_offset_k(address));
	else
		pgd = kernel_to_entry_pgdp(pgd_offset_k(address));

	if (address < PAGE_OFFSET) {
		WARN_ONCE(1, "attempt to walk user address\n");
		return NULL;
	}

	if (pgd_none(*pgd)) {
		unsigned long new_p4d_page = __get_free_page(gfp);
		if (WARN_ON_ONCE(!new_p4d_page))
			return NULL;

		set_pgd(pgd, __pgd(_KERNPG_TABLE | __pa(new_p4d_page)));
	}
	BUILD_BUG_ON(pgd_large(*pgd) != 0);

	return p4d_offset(pgd, address);
}

/*
 * Walk the user copy of the page tables (optionally) trying to allocate
 * page table pages on the way down.
 *
 * Returns a pointer to a PMD on success, or NULL on failure.
 */
static pmd_t *pti_user_pagetable_walk_pmd(unsigned long address, bool entry)
{
	gfp_t gfp = (GFP_KERNEL | __GFP_NOTRACK | __GFP_ZERO);
	p4d_t *p4d;
	pud_t *pud;

	p4d = pti_user_pagetable_walk_p4d(address, entry);
	if (!p4d)
		return NULL;

	BUILD_BUG_ON(p4d_large(*p4d) != 0);
	if (p4d_none(*p4d)) {
		unsigned long new_pud_page = __get_free_page(gfp);
		if (WARN_ON_ONCE(!new_pud_page))
			return NULL;

		set_p4d(p4d, __p4d(_KERNPG_TABLE | __pa(new_pud_page)));
	}

	pud = pud_offset(p4d, address);
	/* The user page tables do not use large mappings: */
	if (pud_large(*pud)) {
		WARN_ON(1);
		return NULL;
	}
	if (pud_none(*pud)) {
		unsigned long new_pmd_page = __get_free_page(gfp);
		if (WARN_ON_ONCE(!new_pmd_page))
			return NULL;

		set_pud(pud, __pud(_KERNPG_TABLE | __pa(new_pmd_page)));
	}

	return pmd_offset(pud, address);
}

/*
 * Walk the shadow copy of the page tables (optionally) trying to allocate
 * page table pages on the way down.  Does not support large pages.
 *
 * Note: this is only used when mapping *new* kernel data into the
 * user/shadow page tables.  It is never used for userspace data.
 *
 * Returns a pointer to a PTE on success, or NULL on failure.
 */
static pte_t *pti_user_pagetable_walk_pte(unsigned long address, bool entry)
{
	gfp_t gfp = (GFP_KERNEL | __GFP_NOTRACK | __GFP_ZERO);
	pmd_t *pmd;
	pte_t *pte;

	pmd = pti_user_pagetable_walk_pmd(address, entry);
	if (!pmd)
		return NULL;

	/* We can't do anything sensible if we hit a large mapping. */
	if (pmd_large(*pmd)) {
		WARN_ON(1);
		return NULL;
	}

	if (pmd_none(*pmd)) {
		unsigned long new_pte_page = __get_free_page(gfp);
		if (!new_pte_page)
			return NULL;

		set_pmd(pmd, __pmd(_KERNPG_TABLE | __pa(new_pte_page)));
	}

	pte = pte_offset_kernel(pmd, address);
	if (pte_flags(*pte) & _PAGE_USER) {
		WARN_ONCE(1, "attempt to walk to user pte\n");
		return NULL;
	}
	return pte;
}

#ifdef CONFIG_X86_VSYSCALL_EMULATION
static void __init pti_setup_vsyscall(void)
{
	pte_t *pte, *target_pte;
	unsigned int level;

	pte = lookup_address(VSYSCALL_ADDR, &level);
	if (!pte || WARN_ON(level != PG_LEVEL_4K) || pte_none(*pte))
		return;

	/* FIXME: entry pt walk*/
	target_pte = pti_user_pagetable_walk_pte(VSYSCALL_ADDR);
	if (WARN_ON(!target_pte))
		return;

	*target_pte = *pte;
	/* FIXME: entry pt walk*/
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
		  enum pti_clone_level level, bool entry)
{
	unsigned long addr;

	/*
	 * Clone the populated PMDs which cover start to end. These PMD areas
	 * can have holes.
	 */
	for (addr = start; addr < end;) {
		pte_t *pte, *target_pte;
		pmd_t *pmd, *target_pmd;
		pgd_t *pgd;
		p4d_t *p4d;
		pud_t *pud;

		/* Overflow check */
		if (addr < start)
			break;

		pgd = pgd_offset_k(addr);
		if (WARN_ON(pgd_none(*pgd)))
			return;
		p4d = p4d_offset(pgd, addr);
		if (WARN_ON(p4d_none(*p4d)))
			return;

		pud = pud_offset(p4d, addr);
		if (pud_none(*pud)) {
			addr += PUD_SIZE;
			continue;
		}

		pmd = pmd_offset(pud, addr);
		if (pmd_none(*pmd)) {
			addr += PMD_SIZE;
			continue;
		}

		if (pmd_large(*pmd) || level == PTI_CLONE_PMD) {
			target_pmd = pti_user_pagetable_walk_pmd(addr, entry);
			if (WARN_ON(!target_pmd))
				return;

			/*
			 * Only clone present PMDs.  This ensures only setting
			 * _PAGE_GLOBAL on present PMDs.  This should only be
			 * called on well-known addresses anyway, so a non-
			 * present PMD would be a surprise.
			 */
			if (WARN_ON(!(pmd_flags(*pmd) & _PAGE_PRESENT)))
				return;

			/*
			 * Setting 'target_pmd' below creates a mapping in both
			 * the user and kernel page tables.  It is effectively
			 * global, so set it as global in both copies.  Note:
			 * the X86_FEATURE_PGE check is not _required_ because
			 * the CPU ignores _PAGE_GLOBAL when PGE is not
			 * supported.  The check keeps consistentency with
			 * code that only set this bit when supported.
			 */
			if (boot_cpu_has(X86_FEATURE_PGE))
				*pmd = pmd_set_flags(*pmd, _PAGE_GLOBAL);

			/*
			 * Copy the PMD.  That is, the kernelmode and usermode
			 * tables will share the last-level page tables of this
			 * address range
			 */
			*target_pmd = *pmd;

			addr += PMD_SIZE;

		} else if (level == PTI_CLONE_PTE) {

			/* Walk the page-table down to the pte level */
			pte = pte_offset_kernel(pmd, addr);
			if (pte_none(*pte)) {
				addr += PAGE_SIZE;
				continue;
			}

			/* Only clone present PTEs */
			if (WARN_ON(!(pte_flags(*pte) & _PAGE_PRESENT)))
				return;

			/* Allocate PTE in the user page-table */
			target_pte = pti_user_pagetable_walk_pte(addr, entry);
			if (WARN_ON(!target_pte))
				return;

			/* Set GLOBAL bit in both PTEs */
			if (boot_cpu_has(X86_FEATURE_PGE))
				*pte = pte_set_flags(*pte, _PAGE_GLOBAL);

			/* Clone the PTE */
			*target_pte = *pte;

			addr += PAGE_SIZE;

		} else {
			BUG();
		}
	}
}

void pti_clone_pgtable_pmd(unsigned long start, unsigned long end, bool entry)
{
	pti_clone_pgtable(start, end, PTI_CLONE_PMD, entry);
}

void pti_clone_pgtable_pte(unsigned long start, unsigned long end, bool entry)
{
	pti_clone_pgtable(start, end, PTI_CLONE_PTE, entry);
}

#ifdef CONFIG_X86_64
/*
 * Clone a single p4d (i.e. a top-level entry on 4-level systems and a
 * next-level entry on 5-level systems.
 */
static void __init pti_clone_p4d(unsigned long addr)
{
	p4d_t *kernel_p4d, *user_p4d;
	pgd_t *kernel_pgd;

#ifdef CONFIG_INTERNAL_PTI
	p4d_t *entry_p4d;
#endif

	user_p4d = pti_user_pagetable_walk_p4d(addr, false);
	if (!user_p4d)
		return;

#ifdef CONFIG_INTERNAL_PTI
	entry_p4d = pti_user_pagetable_walk_p4d(addr, true);
	if (!entry_p4d)
		return;
#endif

	kernel_pgd = pgd_offset_k(addr);
	kernel_p4d = p4d_offset(kernel_pgd, addr);
	*user_p4d = *kernel_p4d;
#ifdef CONFIG_INTERNAL_PTI
	*entry_p4d = *kernel_p4d;
#endif
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
		 * that it's propagated to all mms.  If we were to add one of
		 * these mappings during CPU hotplug, we would need to take
		 * some measure to make sure that every mm that subsequently
		 * ran on that CPU would have the relevant PGD entry in its
		 * pagetables.  The usual vmalloc_fault() mechanism would not
		 * work for page faults taken in entry_SYSCALL_64 before RSP
		 * is set up.
		 */

		unsigned long va = (unsigned long)&per_cpu(cpu_tss_rw, cpu);
		phys_addr_t pa = per_cpu_ptr_to_phys((void *)va);
		pte_t *target_pte;

		target_pte = pti_user_pagetable_walk_pte(va, false);
		if (WARN_ON(!target_pte))
			return;

		*target_pte = pfn_pte(pa >> PAGE_SHIFT, PAGE_KERNEL);

#ifdef CONFIG_INTERNAL_PTI
		target_pte = pti_user_pagetable_walk_pte(va, true);
		if (WARN_ON(!target_pte))
			return;

		*target_pte = pfn_pte(pa >> PAGE_SHIFT, PAGE_KERNEL);
#endif
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

	pti_clone_pgtable(start, end, PTI_CLONE_PMD, false);
#ifdef CONFIG_INTERNAL_PTI
	pti_clone_pgtable(start, end, PTI_CLONE_PMD, true);
#endif
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
 * Clone the populated PMDs of the entry and irqentry text and force it RO.
 */
static void pti_clone_entry_text(void)
{
	pti_clone_pgtable((unsigned long) __entry_text_start,
			  (unsigned long) __irqentry_text_end,
			  PTI_CLONE_PMD, false);
#ifdef CONFIG_INTERNAL_PTI
	pti_clone_pgtable((unsigned long) __entry_text_start,
			  (unsigned long) __irqentry_text_end,
			  PTI_CLONE_PMD, true);
#ifdef CONFIG_RETPOLINE
	pti_clone_pgtable((unsigned long) __indirect_thunk_start,
			  (unsigned long) __indirect_thunk_end,
			  PTI_CLONE_PMD, true);
#endif
#endif
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
 * This is the only user for these and it is not arch-generic
 * like the other set_memory.h functions.  Just extern them.
 */
extern int set_memory_nonglobal(unsigned long addr, int numpages);
extern int set_memory_global(unsigned long addr, int numpages);

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
	unsigned long end_global = PFN_ALIGN((unsigned long)__stop___ex_table);

	if (!pti_kernel_image_global_ok())
		return;

	pr_debug("mapping partial kernel image into user address space\n");

	/*
	 * Note that this will undo _some_ of the work that
	 * pti_set_kernel_image_nonglobal() did to clear the
	 * global bit.
	 */
	pti_clone_pgtable(start, end_clone, PTI_LEVEL_KERNEL_IMAGE, false);
#ifdef CONFIG_INTERNAL_PTI
	pti_clone_pgtable(start, end_clone, PTI_LEVEL_KERNEL_IMAGE, true);
#endif

	/*
	 * pti_clone_pgtable() will set the global bit in any PMDs
	 * that it clones, but we also need to get any PTEs in
	 * the last level for areas that are not huge-page-aligned.
	 */

	/* Set the global bit for normal non-__init kernel text: */
	set_memory_global(start, (end_global - start) >> PAGE_SHIFT);
}

void pti_set_kernel_image_nonglobal(void)
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

static void pti_clone_entry_areas(void)
{
#ifdef CONFIG_INTERNAL_PTI
	pti_clone_pgtable((unsigned long) __entry_data_start,
			  (unsigned long) __entry_data_end,
			  PTI_CLONE_PMD, true);
#endif
}

/*
 * Initialize kernel page table isolation
 */
void __init pti_init(void)
{
	if (!static_cpu_has(X86_FEATURE_PTI))
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
	pti_clone_entry_areas();
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
	pr_info("final\n");

	/*
	 * We need to clone everything (again) that maps parts of the
	 * kernel image.
	 */
	pti_clone_entry_text();
	pti_clone_kernel_text();
	pti_clone_entry_areas();

	debug_checkwx_user();
}

#ifdef CONFIG_INTERNAL_PTI
struct ipti_mapping {
	unsigned long addr;
	pmd_t *pmd;
	pte_t *pte;
};

struct ipti_mm_data {
	unsigned long index;
	unsigned long size;
	struct ipti_mapping mappings[0];
};

int ipti_pgd_alloc(struct mm_struct *mm)
{
	struct ipti_mm_data *ipti_mm_data;

	ipti_mm_data = (struct ipti_mm_data *)__get_free_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!ipti_mm_data)
		return -ENOMEM;

	ipti_mm_data->size = PAGE_SIZE - 2 * sizeof(unsigned long);

	mm->ipti_mapping = ipti_mm_data;
	mm->ipti_pgd = kernel_to_entry_pgdp(mm->pgd);

	return 0;
}

void ipti_pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	struct ipti_mm_data *ipti;

	if (WARN_ON(!mm))
		return;

	ipti = mm->ipti_mapping;
	free_page((unsigned long)ipti);
}

static int ipti_mapping_realloc(struct mm_struct *mm)
{
	return -ENOMEM;
}

static pmd_t *ipti_get_pmd(pgd_t *pgdp, unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;

	pgd = pgd_offset_pgd(pgdp, addr);
	if (WARN_ON(pgd_none(*pgd)))
		return NULL;

	p4d = p4d_offset(pgd, addr);
	if (WARN_ON(p4d_none(*p4d)))
		return NULL;

	pud = pud_offset(p4d, addr);
	if (WARN_ON(pud_none(*pud)))
		return NULL;

	return pmd_offset(pud, addr);
}

static void __ipti_add_mapping(struct ipti_mm_data *ipti, struct mm_struct *mm,
			      unsigned long addr)
{
	pgd_t *pgdp = kernel_to_entry_pgdp(mm->pgd);
	pte_t *pte, *pte_k;
	pmd_t *pmd, *pmd_k;

	pmd_k = ipti_get_pmd(mm->pgd, addr);
	if (WARN_ON(pmd_none(*pmd_k)))
		return;

	pmd = ipti_get_pmd(pgdp, addr);
	if (WARN_ON(pmd_none(*pmd)))
		return;

	if (WARN_ON(!(pmd_flags(*pmd) & _PAGE_PRESENT)))
		return;

	if (pmd_large(*pmd)) {
		pr_info("ADD PMD: entry: %px (%lx), kernel: %px (%lx)\n", pmd, pmd_val(*pmd), pmd_k, pmd_val(*pmd_k));
		ipti->mappings[ipti->index].pmd = pmd;
	} else {
		pte = pte_offset_kernel(pmd, addr);
		if (WARN_ON(pte_none(*pte)))
			return;
		if (WARN_ON(!(pte_flags(*pte) & _PAGE_PRESENT)))
			return;
		pte_k = pte_offset_kernel(pmd_k, addr);
		pr_info("ADD PTE: entry: %px (%lx), kernel: %px (%lx)\n", pte, pte_val(*pte), pte_k, pte_val(*pte_k));
		ipti->mappings[ipti->index].pte = pte;
		/* ipti->mappings[ipti->index].pmd = pmd; */
	}

	ipti->mappings[ipti->index].addr = addr;

	ipti->index++;
}

int ipti_add_mapping(unsigned long address)
{
	struct mm_struct *mm = current->active_mm;
	struct ipti_mm_data *ipti;
	int err = 0;

	if (!mm) {
		pr_err("System call from kernel thread?!\n");
		return -ENOMEM;
	}

	ipti = mm->ipti_mapping;

	if ((ipti->index + 1) * sizeof(*ipti->mappings) > ipti->size) {
		err = ipti_mapping_realloc(mm);
		if (err)
			return err;
	}

	__ipti_add_mapping(ipti, mm, address);
	return 0;
}

static void __ipti_clear_mapping(struct ipti_mapping *m)
{
	if (m->pmd)
		pmd_clear(m->pmd);
	else if (m->pte)
		pte_clear(NULL, 0, m->pte);
	else
		BUG();
}

void ipti_clear_mappins(void)
{
	struct mm_struct *mm = current->active_mm;
	struct ipti_mm_data *ipti;
	int i;

	if (WARN_ON(!mm))
		return;

	ipti = mm->ipti_mapping;

	for (i = 0; i < ipti->index; i++) {
		struct ipti_mapping *m = &ipti->mappings[i];
		pmd_t *pmd = ipti_get_pmd(kernel_to_entry_pgdp(mm->pgd), m->addr);

		pr_info("DEL: addr: %lx, pmd: %px, m->pmd: %px, pte: %px\n", m->addr, pmd, m->pmd, m->pte);
		__ipti_clear_mapping(m);
	}
	local_flush_tlb();
	memset(ipti->mappings, 0, ipti->size);

	ipti->index = 0;
}

/* FIXME: split common code from ?pti_clone_pgtable */
void ipti_clone_pgtable(unsigned long addr)
{
	pte_t *pte, *target_pte, ptev;
	pmd_t *pmd, *target_pmd;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;

	pgd = pgd_offset_k(addr);
	if (WARN_ON(pgd_none(*pgd)))
		return;
	p4d = p4d_offset(pgd, addr);
	if (WARN_ON(p4d_none(*p4d)))
		return;

	pud = pud_offset(p4d, addr);
	if (WARN_ON(pud_none(*pud)))
		return;

	pmd = pmd_offset(pud, addr);
	if (WARN_ON(pmd_none(*pmd)))
		return;

	if (pmd_large(*pmd)) {
		pgprot_t flags;
		unsigned long pa;

		target_pmd = pti_user_pagetable_walk_pmd(addr, true);
		if (WARN_ON(!target_pmd))
			return;

		if (WARN_ON(!(pmd_flags(*pmd) & _PAGE_PRESENT)))
			return;

		if (WARN_ON(pmd_large(*target_pmd)))
			return;

		flags = pmd_pgprot(*pmd);
		pa = __pa(addr);

		ptev = pfn_pte(pa >> PAGE_SHIFT, flags);
	} else {
		/* Walk the page-table down to the pte level */
		pte = pte_offset_kernel(pmd, addr);
		if (WARN_ON(pte_none(*pte)))
			return;

		/* Only clone present PTEs */
		if (WARN_ON(!(pte_flags(*pte) & _PAGE_PRESENT)))
			return;

		ptev = *pte;
	}

	/* Allocate PTE in the user page-table */
	target_pte = pti_user_pagetable_walk_pte(addr, true);
	if (WARN_ON(!target_pte))
		return;

	/* Clone the PTE */
	*target_pte = ptev;
}

static bool ipti_is_code_access_safe(struct pt_regs *regs, unsigned long addr)
{
	char namebuf[KSYM_NAME_LEN];
	const char *symbol, *rip_symbol;
	unsigned long offset, size;
	char *modname;

	pr_info("code: %lx reads %lx\n", regs->ip, addr);

	/* instruction fetch outside kernel or module text */
	if (!(is_kernel_text(addr)) || is_module_text_address(addr))
		return false;

	/* no symbol matches the address */
	symbol = kallsyms_lookup(addr, &size, &offset, &modname, namebuf);
	if (!symbol) {
		pr_err("no symbol at %lx\n", addr);
		return NULL;
	}

	if (symbol != namebuf) {
		pr_err("BPF or ftrace: %s vs %s\n", symbol, namebuf);
		return NULL;
	}

	/*
	 * access in the middle of a function
	 * for now, treat jumps inside a functions as safe.
	 */
	if (offset) {
		rip_symbol = kallsyms_lookup(regs->ip, &size, &offset,
					     &modname, namebuf);
		if (!rip_symbol) {
			pr_err("no symbol for current context: %lx\n", regs->ip);
			return false;
		}

		if (rip_symbol != symbol) {
			pr_err("accessing %s at offset %lx\n", symbol, offset);
			return false;
		}

		/* FIXME: should we check the module names match? */
	}

	return true;
}

static bool ipti_is_data_access_safe(struct pt_regs *regs, unsigned long addr)
{
	pr_info("data: %lx reads %lx\n", regs->ip, addr);
	return true;
}

bool ipti_address_is_safe(struct pt_regs *regs, unsigned long addr,
			  unsigned long hw_error_code)
{
	/* return false; */
	if (hw_error_code & X86_PF_INSTR)
		return ipti_is_code_access_safe(regs, addr);

	return ipti_is_data_access_safe(regs, addr);
}
#endif
