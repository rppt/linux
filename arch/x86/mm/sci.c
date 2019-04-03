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

/* static struct page *sci_pages[4096]; */
/* static int pages_idx; */

struct ipti_mapping {
	/* unsigned long addr; */
	pte_t *pte;
};

struct ipti_data {
	unsigned long size;
	unsigned long pages_index;
	struct page **pages;
	unsigned long rip_index;
	unsigned long rips[256];
	unsigned long index;
	struct ipti_mapping mappings[0];
};

#define IPTI_ORDER 0
#define SCI_PAGES 1024

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

	ipti->pages = kvzalloc(sizeof(struct page *) * SCI_PAGES,
			       GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!ipti->pages) {
		free_pages((unsigned long)ipti, IPTI_ORDER);
		return -ENOMEM;
	}

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
	kfree(ipti->pages);

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
			sci_debug = 0;
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
 * Walk the user copy of the page tables (optionally) trying to allocate
 * page table pages on the way down.
 *
 * Returns a pointer to a P4D on success, or NULL on failure.
 */
static p4d_t *ipti_pagetable_walk_p4d(struct ipti_data *ipti,
				      pgd_t *pgd, unsigned long address)
{
	gfp_t gfp = (GFP_KERNEL | __GFP_ZERO);

	if (address < PAGE_OFFSET) {
		WARN_ONCE(1, "attempt to walk user address\n");
		return NULL;
	}

	if (pgd_none(*pgd)) {
		struct page *page = alloc_page(gfp);
		unsigned long p4d_addr;

		if (WARN_ON_ONCE(!page))
			return NULL;

		p4d_addr = (unsigned long)page_address(page);

		if (sci_debug) {
			pr_info("new p4d: %px (%lx)\n", page, p4d_addr);
			/* dump_page(page, "sci alloc"); */
		}

		if (ipti->pages_index > SCI_PAGES - 10)
			pr_info("%s: addr: %lx, pages: %ld\n", __func__, address, ipti->pages_index);
		BUG_ON(ipti->pages_index > SCI_PAGES - 10);
		ipti->pages[ipti->pages_index++] = page;

		set_pgd(pgd, __pgd(_KERNPG_TABLE | __pa(p4d_addr)));
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
static pmd_t *ipti_pagetable_walk_pmd(struct ipti_data *ipti,
				      pgd_t *pgd, unsigned long address)
{
	gfp_t gfp = (GFP_KERNEL | __GFP_ZERO);
	p4d_t *p4d;
	pud_t *pud;

	p4d = ipti_pagetable_walk_p4d(ipti, pgd, address);
	if (!p4d)
		return NULL;

	BUILD_BUG_ON(p4d_large(*p4d) != 0);
	if (p4d_none(*p4d)) {
		struct page *page = alloc_page(gfp);
		unsigned long pud_addr;

		if (WARN_ON_ONCE(!page))
			return NULL;

		pud_addr = (unsigned long)page_address(page);

		if (sci_debug) {
			pr_info("new pud: %px (%lx), p4d: %px\n", page, pud_addr, p4d);
			/* dump_page(page, "sci alloc"); */
		}

		if (ipti->pages_index > SCI_PAGES - 10)
			pr_info("%s: addr: %lx, pages: %ld\n", __func__, address, ipti->pages_index);
		BUG_ON(ipti->pages_index > SCI_PAGES - 10);
		ipti->pages[ipti->pages_index++] = page;

		set_p4d(p4d, __p4d(_KERNPG_TABLE | __pa(pud_addr)));
	}

	pud = pud_offset(p4d, address);
	/* The user page tables do not use large mappings: */
	if (pud_large(*pud)) {
		WARN_ON(1);
		return NULL;
	}
	if (pud_none(*pud)) {
		struct page *page = alloc_page(gfp);
		unsigned long pmd_addr;

		if (WARN_ON_ONCE(!page))
			return NULL;

		pmd_addr = (unsigned long)page_address(page);

		if (sci_debug) {
			pr_info("new pmd: %px (%lx)\n", page, pmd_addr);
			/* dump_page(page, "sci alloc"); */
		}
		if (ipti->pages_index > SCI_PAGES - 10)
			pr_info("%s: addr: %lx, pages: %ld\n", __func__, address, ipti->pages_index);
		BUG_ON(ipti->pages_index > SCI_PAGES - 10);
		ipti->pages[ipti->pages_index++] = page;

		set_pud(pud, __pud(_KERNPG_TABLE | __pa(pmd_addr)));
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
static pte_t *ipti_pagetable_walk_pte(struct ipti_data *ipti,
				      pgd_t *pgd, unsigned long address)
{
	gfp_t gfp = (GFP_KERNEL | __GFP_ZERO);
	pmd_t *pmd;
	pte_t *pte;

	pmd = ipti_pagetable_walk_pmd(ipti, pgd, address);
	if (!pmd)
		return NULL;

	/* We can't do anything sensible if we hit a large mapping. */
	if (pmd_large(*pmd)) {
		WARN_ON(1);
		return NULL;
	}

	if (pmd_none(*pmd)) {
		struct page *page = alloc_page(gfp);
		unsigned long pte_addr;

		if (!page)
			return NULL;

		pte_addr = (unsigned long)page_address(page);

		if (sci_debug) {
			pr_info("new pte: %px (%lx)\n", page, pte_addr);
			/* dump_page(page, "sci alloc"); */
		}
		if (ipti->pages_index > SCI_PAGES - 10)
			pr_info("%s: addr: %lx, pages: %ld\n", __func__, address, ipti->pages_index);
		BUG_ON(ipti->pages_index > SCI_PAGES - 10);
		ipti->pages[ipti->pages_index++] = page;

		set_pmd(pmd, __pmd(_KERNPG_TABLE | __pa(pte_addr)));
	}

	pte = pte_offset_kernel(pmd, address);
	if (pte_flags(*pte) & _PAGE_USER) {
		WARN_ONCE(1, "attempt to walk to user pte\n");
		return NULL;
	}
	return pte;
}

enum {
	NO_PGD = -1,
	NO_P4D = -2,
	NO_PUD = -3,
	NO_PMD = -4,
	NO_TGT = -5,
};

static int __ipti_clone_pgtable(struct mm_struct *mm,
				 pgd_t *pgdp, pgd_t *target_pgdp,
				 unsigned long addr, bool add)
{
	struct ipti_data *ipti = mm->ipti;
	pte_t *pte, *target_pte, ptev;
	pmd_t *pmd, *target_pmd;
	pgd_t *pgd, *target_pgd;
	p4d_t *p4d;
	pud_t *pud;

	if (sci_debug && add) {
		pr_info("CLONE ==>: %lx\n", addr);
		dump_pagetable(pgdp, addr);
	}

	/* if (sci_debug) */
	/* 	pr_info("addr: %lx PGD: %ld PUD %ld\n", addr, pgd_index(addr), pud_index(addr)); */

	pgd = pgd_offset_pgd(pgdp, addr);
	/* if (WARN_ON(pgd_none(*pgd))) */
	/* 	return; */
	/* p4d = p4d_offset(pgd, addr); */
	/* if (WARN_ON(p4d_none(*p4d))) */
	/* 	return; */

	/* pud = pud_offset(p4d, addr); */
	/* if (WARN_ON(pud_none(*pud))) */
	/* 	return; */

	/* pmd = pmd_offset(pud, addr); */
	/* if (WARN_ON(pmd_none(*pmd))) */
	/* 	return; */

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

		target_pmd = ipti_pagetable_walk_pmd(ipti, target_pgd, addr);
		if (WARN_ON(!target_pmd))
			return NO_TGT;

		if (WARN_ON(!(pmd_flags(*pmd) & _PAGE_PRESENT)))
			return NO_TGT;

		if (WARN_ON(pmd_large(*target_pmd)))
			return NO_TGT;

		flags = pte_pgprot(pte_clrhuge(*(pte_t *)pmd));
		pfn = pmd_pfn(*pmd) + pte_index(addr);
		ptev = pfn_pte(pfn, flags);
	} else {
		/* Walk the page-table down to the pte level */
		pte = pte_offset_kernel(pmd, addr);
		/* if (WARN_ON(pte_none(*pte))) */
		/* 	return; */

		/* /\* Only clone present PTEs *\/ */
		/* /\* if (WARN_ON(!(pte_flags(*pte) & _PAGE_PRESENT))) *\/ */
		/* if (!(pte_flags(*pte) & _PAGE_PRESENT)) */
		/* 	pr_info("PTE !P: %lx\n", pte_val(*pte)); */
		/* return; */

		ptev = *pte;
	}

	/* Allocate PTE in the entry page-table */
	target_pte = ipti_pagetable_walk_pte(ipti, target_pgd, addr);
	if (WARN_ON(!target_pte))
		return NO_TGT;

	/* /\* Clone the PTE *\/ */
	/* if (!pte_none(*target_pte)) { */
	/* 	if (pte_val(*target_pte) == pte_val(ptev)) */
	/* 		return 0; */
	/* 	pr_info("old: %lx, new: %lx\n", pte_val(*target_pte), pte_val(ptev)); */
	/* } */

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

	sci_debug = 1;

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

/* static int sci_clone_pmd_range(pmd_t *dst, pmd_t *src) */
/* { */
/* 	gfp_t gfp = (GFP_KERNEL | __GFP_ZERO); */
/* 	pmd_t *s_pmd, *d_pmd; */
/* 	pte_t *s_pte, *d_pte; */
/* 	int i; */

/* 	pr_info("PMD: src: %px dst: %px\n", src, dst); */

/* 	for (s_pmd = src, d_pmd = dst; s_pmd < src + PTRS_PER_PMD; */
/* 	     s_pmd++, d_pmd++) { */
/* 		if (pmd_none(*s_pmd)) */
/* 			continue; */

/* 		s_pte = phys_to_virt(PFN_PHYS(pmd_pfn(*s_pmd))); */
/* 		d_pte = (pte_t *)__get_free_page(gfp); */
/* 		if (!d_pte) */
/* 			return -ENOMEM; */

/* 		pr_info("NEW PTE: %px\n", d_pte); */

/* 		set_pmd(d_pmd, __pmd(_KERNPG_TABLE | __pa(d_pte))); */

/* 		/\* for (i = 0; i < PTRS_PER_PTE; i++) { *\/ */
/* 		/\* 	pte_t *ss_pte, *dd_pte; *\/ */

/* 		/\* 	ss_pte = &s_pte[i]; *\/ */
/* 		/\* 	dd_pte = &d_pte[i]; *\/ */

/* 		/\* 	if (!pte_none(*ss_pte)) { *\/ */
/* 		/\* 		pr_info("SET %d: %px to %lx\n", i, dd_pte, pte_val(*ss_pte)); *\/ */
/* 		/\* 		*dd_pte = *ss_pte; *\/ */
/* 		/\* 	} *\/ */
/* 		/\* } *\/ */

/* 		memcpy(d_pte, s_pte, PAGE_SIZE); */
/* 	} */

/* 	return 0; */
/* } */

/* static int sci_clone_pud_range(pud_t *dst, pud_t *src) */
/* { */
/* 	gfp_t gfp = (GFP_KERNEL | __GFP_ZERO); */
/* 	pud_t *s_pud, *d_pud; */
/* 	pmd_t *s_pmd, *d_pmd; */
/* 	int ret; */

/* 	pr_info("PUD: src: %px dst: %px\n", src, dst); */
/* 	for (s_pud = src, d_pud = dst; s_pud < src + PTRS_PER_PUD; */
/* 	     s_pud++, d_pud++) { */
/* 		if (pud_none(*s_pud)) */
/* 			continue; */

/* 		s_pmd = phys_to_virt(PFN_PHYS(pud_pfn(*s_pud))); */
/* 		d_pmd = (pmd_t *)__get_free_page(gfp); */
/* 		if (!d_pmd) */
/* 			return -ENOMEM; */

/* 		pr_info("NEW PMD: %px\n", d_pmd); */

/* 		set_pud(d_pud, __pud(_KERNPG_TABLE | __pa(d_pmd))); */

/* 		ret = sci_clone_pmd_range(d_pmd, s_pmd); */
/* 		if (ret) */
/* 			return ret; */
/* 	} */

/* 	return 0; */
/* } */

/* static int sci_clone_p4d_range(p4d_t *dst, p4d_t *src) */
/* { */
/* 	gfp_t gfp = (GFP_KERNEL | __GFP_ZERO); */
/* 	p4d_t *s_p4d, *d_p4d; */
/* 	pud_t *s_pud, *d_pud; */
/* 	int ret; */

/* 	pr_info("P4D: src: %px dst: %px\n", src, dst); */
/* 	for (s_p4d = src, d_p4d = dst; s_p4d < src + PTRS_PER_P4D; */
/* 	     s_p4d++, d_p4d++) { */
/* 		if (p4d_none(*s_p4d)) */
/* 			continue; */

/* 		s_pud = phys_to_virt(PFN_PHYS(p4d_pfn(*s_p4d))); */
/* 		d_pud = (pud_t *)__get_free_page(gfp); */
/* 		if (!d_pud) */
/* 			return -ENOMEM; */

/* 		pr_info("NEW PUD: %px\n", d_pud); */

/* 		set_p4d(d_p4d, __p4d(_KERNPG_TABLE | __pa(d_pud))); */

/* 		ret = sci_clone_pud_range(d_pud, s_pud); */
/* 		if (ret) */
/* 			return ret; */
/* 	} */

/* 	return 0; */
/* } */


/* static int sci_clone_pdg_range(pgd_t *dst, pgd_t *src, int count) */
/* { */
/* 	gfp_t gfp = (GFP_KERNEL | __GFP_ZERO); */
/* 	pgd_t *s_pgd, *d_pgd; */
/* 	p4d_t *s_p4d, *d_p4d; */
/* 	int ret; */

/* 	pr_info("PGD: src: %px dst: %px cnt: %d\n", src, dst, count); */
/* 	for (s_pgd = src, d_pgd = dst; s_pgd < src + count; s_pgd++, d_pgd++) { */
/* 		if (pgd_none(*s_pgd)) */
/* 			continue; */

/* 		s_p4d = phys_to_virt(PFN_PHYS(pgd_pfn(*s_pgd))); */
/* 		d_p4d = (p4d_t *)__get_free_page(gfp); */
/* 		if (!d_p4d) */
/* 			return -ENOMEM; */

/* 		pr_info("NEW P4D: %px\n", d_p4d); */

/* 		set_pgd(d_pgd, __pgd(_KERNPG_TABLE | __pa(d_p4d))); */

/* 		ret = sci_clone_p4d_range(d_p4d, s_p4d); */
/* 		if (ret) */
/* 			return ret; */
/* 	} */

/* 	return 0; */
/* } */

/* /\* clone_pgd_range(pgd + KERNEL_PGD_BOUNDARY, *\/ */
/* /\* 		swapper_pg_dir + KERNEL_PGD_BOUNDARY, *\/ */
/* /\* 		KERNEL_PGD_PTRS); *\/ */


/* int sci_clone_entry_pgtable(struct mm_struct *mm) */
/* { */
/* 	pgd_t *k_pgd, *u_pgd, *e_pgd; */

/* 	if (!mm && mm == &init_mm) */
/* 		return 0; */

/* 	k_pgd = mm->pgd + KERNEL_PGD_BOUNDARY; */
/* 	u_pgd = kernel_to_user_pgdp(k_pgd); */
/* 	e_pgd = kernel_to_entry_pgdp(k_pgd); */

/* 	return sci_clone_pdg_range(e_pgd, u_pgd, KERNEL_PGD_PTRS); */
/* } */

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
	int i;

	/* __native_flush_tlb_global(); */
	/* __native_flush_tlb(); */

	/* for (i = ipti->pages_index - 1; i >= 0; i--) { */
	/* 	/\* dump_page(sci_pages[i], "sci free"); *\/ */
	/* 	__free_page(ipti->pages[i]); */
	/* } */

	/* pages_idx = 0; */
	/* pgd_t *pgd; */

	/* for (pgd = pgdp; pgd < pgdp + PTRS_PER_PGD; pgd++) { */
	/* 	if (pgd_none_or_clear_bad(pgd)) */
	/* 		continue; */
	/* 	sci_free_p4d_range(pgd); */
	/* } */
}

static int sci_free_pte_range(struct mm_struct *mm, pmd_t *pmd)
{
	pte_t *pte, *ptep;
	int i;

	ptep = pte_offset_kernel(pmd, 0);

	for (i = 0, pte = ptep; i < PTRS_PER_PTE; i++, pte++) {
		if (pte_none(*pte))
			continue;
		if (sci_debug)
			pr_info("%s: %d: %px\n", __func__, i, pte);
	}

	pmd_clear(pmd);
	pte_free_kernel(mm, ptep);

	return 0;
}

static int sci_free_pmd_range(struct mm_struct *mm, pud_t *pud)
{
	pmd_t *pmd, *pmdp;
	int i;

	pmdp = pmd_offset(pud, 0);

	for (i = 0, pmd = pmdp; i < PTRS_PER_PMD; i++, pmd++) {
		if (pmd_none(*pmd))
			continue;
		sci_free_pte_range(mm, pmd);
		if (sci_debug)
			pr_info("%s: %d: %px\n", __func__, i, pmd);
	}

	pud_clear(pud);
	pte_free_kernel(mm, (pte_t*)pmdp);

	return 0;
}

static int sci_free_pud_range(struct mm_struct *mm, p4d_t *p4d)
{
	pud_t *pud, *pudp;
	int i;

	pudp = pud_offset(p4d, 0);

	for (i = 0, pud = pudp; i < PTRS_PER_PUD; i++, pud++) {
		if (pud_none(*pud))
			continue;
		sci_free_pmd_range(mm, pud);
		if (sci_debug)
			pr_info("%s: %d: %px\n", __func__, i, pud);
	}

	p4d_clear(p4d);
	pud_free(mm, pudp);

	return 0;
}

static int sci_free_p4d_range(struct mm_struct *mm, pgd_t *pgd)
{
	p4d_t *p4d, *p4dp;
	int i;

	p4dp = p4d_offset(pgd, 0);

	for (i = 0, p4d = p4dp; i < PTRS_PER_P4D; i++, p4d++) {
		if (p4d_none(*p4d))
			continue;
		sci_free_pud_range(mm, p4d);
		if (sci_debug)
			pr_info("%s: %d: %px\n", __func__, i, p4d);
	}

	pgd_clear(pgd);
	p4d_free(mm, p4dp);

	return 0;
}

static int sci_free_page_range(struct mm_struct *mm)
{
	pgd_t *pgdp, *pgd;
	int i;

	pgdp = kernel_to_entry_pgdp(mm->pgd);

	for (i = 0, pgd = pgdp; i < PTRS_PER_PGD; i++, pgd++) {
		if (pgdp_maps_userspace(pgd))
			continue;
		if (!pgd_present(*pgd))
			continue;
		sci_free_p4d_range(mm, pgd);
		if (sci_debug)
			pr_info("%s: %d: %px: %lx\n", __func__, i, pgd, pgd_val(*pgd));
	}

	sci_debug = 0;

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
