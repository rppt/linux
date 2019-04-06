// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright(c) 2019 IBM Corporation. All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/sizes.h>

#include <asm/cpufeature.h>
#include <asm/hypervisor.h>
#include <asm/cmdline.h>
#include <asm/sci.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/desc.h>
#include <asm/sections.h>
#include <asm/traps.h>

#undef pr_fmt
#define pr_fmt(fmt)     "SCI: " fmt

static u8 sci_debug;

static int bad_address(void *p)
{
	unsigned long dummy;

	return probe_kernel_address((unsigned long *)p, dummy);
}

static void dump_pagetable(pgd_t *base, unsigned long address)
{
	/* pgd_t *base = __va(read_cr3_pa()); */
	pgd_t *pgd = base + pgd_index(address);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (bad_address(pgd))
		goto bad;

	pr_info("PGD %lx ", pgd_val(*pgd));

	if (!pgd_present(*pgd))
		goto out;

	p4d = p4d_offset(pgd, address);
	if (bad_address(p4d))
		goto bad;

	pr_cont("P4D %lx ", p4d_val(*p4d));
	if (!p4d_present(*p4d) || p4d_large(*p4d))
		goto out;

	pud = pud_offset(p4d, address);
	if (bad_address(pud))
		goto bad;

	pr_cont("PUD %lx ", pud_val(*pud));
	if (!pud_present(*pud) || pud_large(*pud))
		goto out;

	pmd = pmd_offset(pud, address);
	if (bad_address(pmd))
		goto bad;

	pr_cont("PMD %lx ", pmd_val(*pmd));
	if (!pmd_present(*pmd) || pmd_large(*pmd))
		goto out;

	pte = pte_offset_kernel(pmd, address);
	if (bad_address(pte))
		goto bad;

	pr_cont("PTE %lx", pte_val(*pte));
out:
	pr_cont("\n");
	return;
bad:
	pr_info("BAD\n");
}

struct ipti_mapping {
	/* unsigned long addr; */
	pte_t *pte;
};

struct ipti_data {
	unsigned long size;
	unsigned long rip_index;
	unsigned long rips[256];
	unsigned long index;
	struct ipti_mapping mappings[0];
};

#define IPTI_ORDER 0

static void sci_clone_user_shared(struct mm_struct *mm);
static void sci_clone_entry_text(struct mm_struct *mm);
static void sci_dump_debug_info(struct mm_struct *mm, const char *msg, bool last);
static int __ipti_clone_pgtable(struct mm_struct *mm,
				pgd_t *pgdp, pgd_t *target_pgdp,
				unsigned long addr, bool add);
static int sci_free_page_range(struct mm_struct *mm);

static inline void ipti_map_stack(struct task_struct *tsk, struct mm_struct *mm)
{
	unsigned long stack = (unsigned long)tsk->stack;
	unsigned long addr;

	for (addr = stack; addr < stack + THREAD_SIZE; addr += PAGE_SIZE)
		__ipti_clone_pgtable(mm, mm->pgd, kernel_to_entry_pgdp(mm->pgd),
				     addr, false);

}

/* int ipti_pgd_alloc(struct mm_struct *mm) */
int sci_init(struct task_struct *tsk, struct mm_struct *mm)
{

	struct ipti_data *ipti;

	/* if (!sci_debug && current->pid == 1) */
	/* 	sci_debug = 1; */
	/* else */
	/* 	sci_debug = 0; */

	if (sci_debug)
		pr_info("%s: %d: mm: %px stack: %px\n", __func__, current->pid, mm, current->stack);

	ipti = (struct ipti_data *)__get_free_pages(GFP_KERNEL_ACCOUNT | __GFP_ZERO, IPTI_ORDER);
	if (!ipti)
		return -ENOMEM;

	mm->ipti = ipti;

	ipti->size = (PAGE_SIZE << IPTI_ORDER) - sizeof(*ipti);

	/* sci_dump_debug_info(mm, "init 1", false); */

	sci_clone_user_shared(mm);
	sci_clone_entry_text(mm);
	ipti_map_stack(tsk, mm);
	sci_dump_debug_info(mm, "init", false);

	/* if (current->pid == 1) */
	/* 	sci_debug = 0; */

	return 0;
}

void sci_free_pgd(struct ipti_data *ipti);

void ipti_pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	struct ipti_data *ipti;

	if (WARN_ON(!mm))
		return;

	ipti = mm->ipti;

	sci_free_page_range(mm);

	sci_free_pgd(ipti);

	free_pages((unsigned long)ipti, IPTI_ORDER);
}

static void __ipti_clear_mapping(struct ipti_mapping *m)
{
	if (WARN_ON(!m->pte))
		return;

	pte_clear(NULL, 0, m->pte);
}

void ipti_clear_mappins(void)
{
	struct mm_struct *mm = current->active_mm;
	struct ipti_data *ipti;
	int i;

	if (WARN_ON(!mm))
		return;

	ipti = mm->ipti;

	for (i = 0; i < ipti->index; i++) {
		struct ipti_mapping *m = &ipti->mappings[i];
		__ipti_clear_mapping(m);
	}

	memset(ipti->mappings, 0, ipti->size);
	memset(ipti->rips, 0, sizeof(ipti->rips));
	ipti->index = 0;
	ipti->rip_index = 0;
}

static int ipti_mapping_realloc(struct mm_struct *mm)
{
	return -ENOMEM;
}

static int ipti_add_mapping(unsigned long addr, pte_t *pte)
{
	struct mm_struct *mm = current->active_mm;
	struct ipti_data *ipti;
	int i, err = 0;

	if (!mm) {
		pr_err("System call from kernel thread?!\n");
		return -ENOMEM;
	}

	ipti = mm->ipti;

	for (i = ipti->index - 1; i >=0; i--)
		if (pte == ipti->mappings[ipti->index].pte)
			return 0;

	if ((ipti->index + 1) * sizeof(*ipti->mappings) > ipti->size) {
		err = ipti_mapping_realloc(mm);
		if (err) {
			/* sci_debug = 0; */
			pr_err("can realloc, idx: %ld, size: %ld\n", ipti->index, ipti->size);
			BUG();
			return err;
		}
	}


	/* ipti->mappings[ipti->index].addr = addr; */
	ipti->mappings[ipti->index].pte = pte;
	ipti->index++;

	return 0;
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
static pte_t *ipti_pagetable_walk_pte(struct mm_struct *mm,
				      pgd_t *pgd, unsigned long address)
{
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	p4d = p4d_alloc(mm, pgd, address);
	if (!p4d)
		return NULL;
	pud = pud_alloc(mm, p4d, address);
	if (!pud)
		goto free_p4d;
	pmd = pmd_alloc(mm, pud, address);
	if (!pmd)
		goto free_pud;
	if (__pte_alloc(mm, pmd))
		goto free_pmd;

	return pte_offset_kernel(pmd, address);

free_pmd:
	pmd_free(mm, pmd);
	mm_dec_nr_pmds(mm);
free_pud:
	pud_free(mm, pud);
	mm_dec_nr_puds(mm);
free_p4d:
	p4d_free(mm, p4d);
	return NULL;
}

enum {
	NO_PGD = -1,
	NO_P4D = -2,
	NO_PUD = -3,
	NO_PMD = -4,
	NO_PTE = -5,
	NO_TGT = -6,
};

static int __ipti_clone_pgtable(struct mm_struct *mm,
				 pgd_t *pgdp, pgd_t *target_pgdp,
				 unsigned long addr, bool add)
{
	pte_t *pte, *target_pte, ptev;
	pgd_t *pgd, *target_pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	if (sci_debug && add) {
		pr_info("CLONE ==>: %lx\n", addr);
		dump_pagetable(pgdp, addr);
	}

	pgd = pgd_offset_pgd(pgdp, addr);
	if (pgd_none(*pgd))
		return NO_PGD;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d))
		return NO_P4D;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return NO_PUD;

	if (pud_large(*pud)) {
		pr_info("large PUD: %lx\n", addr);
		dump_pagetable(pgdp, addr);
		return NO_PUD;
	} else {
		pmd = pmd_offset(pud, addr);
		if (pmd_none(*pmd))
			return NO_PMD;
	}

	target_pgd = pgd_offset_pgd(target_pgdp, addr);

	if (pmd_large(*pmd)) {
		pgprot_t flags;
		unsigned long pfn;


		flags = pte_pgprot(pte_clrhuge(*(pte_t *)pmd));
		pfn = pmd_pfn(*pmd) + pte_index(addr);
		ptev = pfn_pte(pfn, flags);
	} else {
		/* Walk the page-table down to the pte level */
		pte = pte_offset_kernel(pmd, addr);
		if (pte_none(*pte) || !(pte_flags(*pte) & _PAGE_PRESENT))
			return NO_PTE;

		ptev = *pte;
	}

	/* Allocate PTE in the entry page-table */
	target_pte = ipti_pagetable_walk_pte(mm, target_pgd, addr);
	if (WARN_ON(!target_pte))
		return NO_TGT;

	*target_pte = ptev;

	if (add)
		WARN_ON(ipti_add_mapping(addr, target_pte));

	if (sci_debug && add) {
		pr_info("<=== CLONE %lx\n", addr);
		dump_pagetable(target_pgdp, addr);
		if (addr > (unsigned long)vmemmap &&
		    addr < (unsigned long)(vmemmap + SZ_1G)) {
			struct page *page = (struct page *)(addr - 8);
			dump_page(page, "sci");
		}
	}

	return 0;
}

void ipti_clone_pgtable(unsigned long addr)
{
	int ret = __ipti_clone_pgtable(current->mm, current->mm->pgd,
				       kernel_to_entry_pgdp(current->mm->pgd),
				       addr, true);
	if (ret)
		pr_info("%s: %d\n", __func__, ret);
}

static bool ipti_is_code_access_safe(struct pt_regs *regs, unsigned long addr)
{
	struct mm_struct *mm = current->active_mm;
	struct ipti_data *ipti;
	char namebuf[KSYM_NAME_LEN];
	const char *symbol;
	unsigned long offset, size;
	char *modname;

	/* sci_debug = 1; */

	if (!mm) {
		pr_err("System call from kernel thread?!\n");
		return false;
	}

	ipti = mm->ipti;

	/* struct unwind_state state; */

	/* pr_info("code: %lx reads %lx\n", regs->ip, addr); */

	/* instruction fetch outside kernel or module text */
	if (!(is_kernel_text(addr) || is_module_text_address(addr))) {
		pr_err("not text\n");
		return false;
	}

	/* no symbol matches the address */
	symbol = kallsyms_lookup(addr, &size, &offset, &modname, namebuf);
	if (!symbol) {
		pr_err("no symbol at %lx\n", addr);
		return false;
	}

	pr_info("sym: %s, name: %s, sz: %ld, off: %lx\n", symbol, namebuf, size, offset);
	if (symbol != namebuf) {
		pr_err("BPF or ftrace: %s vs %s\n", symbol, namebuf);
		return false;
	}

	/* call/jmp <symbol> */
	if (offset) {
		int i = 0;

		for (i = ipti->rip_index - 1; i >= 0; i--) {
			unsigned long rip = ipti->rips[i];

			if ((addr >> PAGE_SHIFT) == ((rip >> PAGE_SHIFT) + 1))
				return true;
		}

		pr_err("offset is too far: off: %lx, addr: %lx\n", offset, addr);
		return false;
	}

	/* dump_stack(); */
	/* caller_stack = unwind_start(&state, current, regs, NULL); */
	/* stack = stack ? : get_stack_pointer(task, regs); */

	/*
	 * access in the middle of a function
	 * for now, treat jumps inside a functions as safe.
	 */

	if (ipti->rip_index > 255)
		return false;

	ipti->rips[ipti->rip_index++] = regs->ip;

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

pgd_t __sci_set_user_pgtbl(pgd_t *pgdp, pgd_t pgd)
{
	if (!pgdp_maps_userspace(pgdp))
		return pgd;

	if (sci_debug) {
		unsigned long ptr = (unsigned long)pgdp;
		unsigned long idx = (ptr & ~PAGE_MASK) / sizeof(pgd_t);

		pr_info("SET USER: pgd: %px idx: %ld\n", pgdp, idx);
	}

	kernel_to_entry_pgdp(pgdp)->pgd = pgd.pgd;

	if ((pgd.pgd & (_PAGE_USER|_PAGE_PRESENT)) == (_PAGE_USER|_PAGE_PRESENT) &&
	    (__supported_pte_mask & _PAGE_NX))
		pgd.pgd |= _PAGE_NX;

	return pgd;
}

static void sci_clone_user_shared(struct mm_struct *mm)
{
	unsigned long addr;
	unsigned int cpu;
	int ret;

	for (addr = CPU_ENTRY_AREA_BASE;
	     addr <= CPU_ENTRY_AREA_BASE + CPU_ENTRY_AREA_MAP_SIZE;
	     addr += PAGE_SIZE) {
		ret = __ipti_clone_pgtable(mm,
					   kernel_to_user_pgdp(mm->pgd),
					   kernel_to_entry_pgdp(mm->pgd),
					   addr, false);
		/* if (ret && sci_debug) */
		/* 	pr_err("%s: addr: %lx: ret: %d\n", __func__, addr, ret); */
	}


	for_each_possible_cpu(cpu) {
		addr = (unsigned long)&per_cpu(cpu_tss_rw, cpu);
		ret = __ipti_clone_pgtable(mm,
					   kernel_to_user_pgdp(mm->pgd),
					   kernel_to_entry_pgdp(mm->pgd),
					   addr, false);
		/* if (ret && sci_debug) */
		/* 	pr_err("%s: addr: %lx: ret: %d\n", __func__, addr, ret); */
	}
}

static void sci_clone_entry_text(struct mm_struct *mm)
{
	unsigned long addr;
	int ret;

	for (addr = (unsigned long) __entry_text_start;
	     addr <= (unsigned long) __irqentry_text_end;
	     addr += PAGE_SIZE) {
		ret = __ipti_clone_pgtable(mm,
					   kernel_to_user_pgdp(mm->pgd),
					   kernel_to_entry_pgdp(mm->pgd),
					   addr, false);
		/* if (ret && sci_debug) */
		/* 	pr_err("%s: addr: %lx: ret: %d\n", __func__, addr, ret); */
	}
}

static void sci_dump_debug_info(struct mm_struct *mm, const char *msg, bool last)
{
	unsigned long addr = (unsigned long)&per_cpu(cpu_tss_rw, 0);

	if (!sci_debug)
		return;

	pr_info("========= %s ===========\n", msg);

	pr_info("mm: %px, pgd: %px\n", mm, mm->pgd);
	pr_info("u_pgd: %px, e_pgd: %px\n", kernel_to_user_pgdp(mm->pgd),
		kernel_to_entry_pgdp(mm->pgd));

	dump_pagetable(kernel_to_user_pgdp(mm->pgd), addr);
	dump_pagetable(kernel_to_user_pgdp(mm->pgd), CPU_ENTRY_AREA_BASE);
	dump_pagetable(kernel_to_user_pgdp(mm->pgd), (unsigned long) __entry_text_start);
	/* ptdump_walk_pgd_level(NULL, kernel_to_user_pgdp(mm->pgd)); */

	pr_info("--------------------\n");

	dump_pagetable(kernel_to_entry_pgdp(mm->pgd), addr);
	dump_pagetable(kernel_to_entry_pgdp(mm->pgd), CPU_ENTRY_AREA_BASE);
	dump_pagetable(kernel_to_entry_pgdp(mm->pgd), (unsigned long) __entry_text_start);
	/* ptdump_walk_pgd_level(NULL, kernel_to_entry_pgdp(mm->pgd)); */
}

/*
 * This function frees user-level page tables of a process.
 */
void sci_free_pgd(struct ipti_data *ipti)
{
}

static int sci_free_pte_range(struct mm_struct *mm, pmd_t *pmd)
{
	pte_t *ptep = pte_offset_kernel(pmd, 0);

	pmd_clear(pmd);
	pte_free(mm, virt_to_page(ptep));
	mm_dec_nr_ptes(mm);

	return 0;
}

static int sci_free_pmd_range(struct mm_struct *mm, pud_t *pud)
{
	pmd_t *pmd, *pmdp;
	int i;

	pmdp = pmd_offset(pud, 0);

	for (i = 0, pmd = pmdp; i < PTRS_PER_PMD; i++, pmd++)
		if (!pmd_none(*pmd))
			sci_free_pte_range(mm, pmd);

	pud_clear(pud);
	pmd_free(mm, pmdp);
	mm_dec_nr_pmds(mm);

	return 0;
}

static int sci_free_pud_range(struct mm_struct *mm, p4d_t *p4d)
{
	pud_t *pud, *pudp;
	int i;

	pudp = pud_offset(p4d, 0);

	for (i = 0, pud = pudp; i < PTRS_PER_PUD; i++, pud++)
		if (!pud_none(*pud))
			sci_free_pmd_range(mm, pud);

	p4d_clear(p4d);
	pud_free(mm, pudp);
	mm_dec_nr_puds(mm);

	return 0;
}

static int sci_free_p4d_range(struct mm_struct *mm, pgd_t *pgd)
{
	p4d_t *p4d, *p4dp;
	int i;

	p4dp = p4d_offset(pgd, 0);

	for (i = 0, p4d = p4dp; i < PTRS_PER_P4D; i++, p4d++)
		if (!p4d_none(*p4d))
			sci_free_pud_range(mm, p4d);

	pgd_clear(pgd);
	p4d_free(mm, p4dp);

	return 0;
}

static int sci_free_page_range(struct mm_struct *mm)
{
	pgd_t *pgdp, *pgd;

	pgdp = kernel_to_entry_pgdp(mm->pgd);

	for (pgd = pgdp + KERNEL_PGD_BOUNDARY; pgd < pgdp + PTRS_PER_PGD; pgd++)
		if (!pgd_none(*pgd))
			sci_free_p4d_range(mm, pgd);

	return 0;
}

static int sci_subsys_init(void)
{
	unsigned long addr = (unsigned long)&per_cpu(cpu_tss_rw, 0);

	pr_info("PGD KERN: %ld\n", PGD_KERNEL_START);
	pr_info("CPU_ENTRY: %ld\n", pgd_index(CPU_ENTRY_AREA_BASE));
	pr_info("TSS: %ld\n", pgd_index(addr));
	pr_info("ENTRY_TEXT: %ld\n", pgd_index((unsigned long) __entry_text_start));

	debugfs_create_u8("sci", 0644, NULL, &sci_debug);

	return 0;
}
late_initcall(sci_subsys_init);
