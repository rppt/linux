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

struct ipti_mapping {
	/* unsigned long addr; */
	pte_t *pte;
};

struct ipti_data {
	unsigned long size;
	unsigned long page_index;
	struct page  *pages[128];
	unsigned long rip_index;
	unsigned long rips[128];
	unsigned long index;
	struct ipti_mapping mappings[0];
};

#define IPTI_ORDER 0

int ipti_pgd_alloc(struct mm_struct *mm)
{
	struct ipti_data *ipti;

	ipti = (struct ipti_data *)__get_free_pages(GFP_KERNEL_ACCOUNT | __GFP_ZERO, IPTI_ORDER);
	if (!ipti)
		return -ENOMEM;

	ipti->size = (PAGE_SIZE << IPTI_ORDER) - sizeof(*ipti);

	mm->context.ipti = ipti;

	return 0;
}

void ipti_pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	struct ipti_data *ipti;
	int i;

	if (WARN_ON(!mm))
		return;

	ipti = mm->context.ipti;

	/* FIXME: actually free the pages */
	/* for (i = 0; i < ipti->page_index; i++) { */
	/* 	struct page *page = ipti->pages[i]; */

	/* 	__free_page(page); */
	/* } */

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

	ipti = mm->context.ipti;

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
	int err = 0;

	if (!mm) {
		pr_err("System call from kernel thread?!\n");
		return -ENOMEM;
	}

	ipti = mm->context.ipti;

	if ((ipti->index + 1) * sizeof(*ipti->mappings) > ipti->size) {
		err = ipti_mapping_realloc(mm);
		if (err) {
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

		if (system_state == SYSTEM_RUNNING)
			pr_info("new p4d: %px (%lx)\n", page, p4d_addr);

		if (WARN_ON(ipti->page_index >= 100))
			return NULL;
		ipti->pages[ipti->page_index++] = page;

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

		if (system_state == SYSTEM_RUNNING)
			pr_info("new pud: %px (%lx), p4d: %px\n", page, pud_addr, p4d);

		if (WARN_ON(ipti->page_index >= 100))
			return NULL;
		ipti->pages[ipti->page_index++] = page;

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

		if (system_state == SYSTEM_RUNNING)
			pr_info("new pmd: %px (%lx)\n", page, pmd_addr);

		if (WARN_ON(ipti->page_index >= 100))
			return NULL;
		ipti->pages[ipti->page_index++] = page;

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

		if (system_state == SYSTEM_RUNNING)
			pr_info("new pte: %px (%lx)\n", page, pte_addr);

		if (WARN_ON(ipti->page_index >= 100))
			return NULL;
		ipti->pages[ipti->page_index++] = page;

		set_pmd(pmd, __pmd(_KERNPG_TABLE | __pa(pte_addr)));
	}

	pte = pte_offset_kernel(pmd, address);
	if (pte_flags(*pte) & _PAGE_USER) {
		WARN_ONCE(1, "attempt to walk to user pte\n");
		return NULL;
	}
	return pte;
}

void ipti_clone_pgtable(unsigned long addr)
{
	struct ipti_data *ipti = current->mm->context.ipti;
	pte_t *pte, *target_pte, ptev;
	pmd_t *pmd, *target_pmd;
	pgd_t *pgd, *target_pgd;
	p4d_t *p4d;
	pud_t *pud;

	pgd = pgd_offset(current->mm, addr);
	if (WARN_ON(pgd_none(*pgd)))
		BUG();
	p4d = p4d_offset(pgd, addr);
	if (WARN_ON(p4d_none(*p4d)))
		BUG();

	pud = pud_offset(p4d, addr);
	if (WARN_ON(pud_none(*pud)))
		BUG();

	pmd = pmd_offset(pud, addr);
	if (WARN_ON(pmd_none(*pmd)))
		BUG();

	target_pgd = kernel_to_entry_pgdp(pgd);

	if (pmd_large(*pmd)) {
		pgprot_t flags;
		unsigned long pa;

		target_pmd = ipti_pagetable_walk_pmd(ipti, target_pgd, addr);
		if (WARN_ON(!target_pmd))
			return;

		if (WARN_ON(!(pmd_flags(*pmd) & _PAGE_PRESENT)))
			return;

		if (WARN_ON(pmd_large(*target_pmd)))
			return;

		flags = pte_pgprot(pte_clrhuge(*(pte_t *)pmd));
		/* flags = pmd_pgprot(*pmd); */
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

	/* Allocate PTE in the entry page-table */
	target_pte = ipti_pagetable_walk_pte(ipti, target_pgd, addr);
	if (WARN_ON(!target_pte))
		return;

	/* Clone the PTE */
	*target_pte = ptev;

	WARN_ON(ipti_add_mapping(addr, target_pte));
}

static bool ipti_is_code_access_safe(struct pt_regs *regs, unsigned long addr)
{
	struct mm_struct *mm = current->active_mm;
	struct ipti_data *ipti;
	char namebuf[KSYM_NAME_LEN];
	const char *symbol;
	unsigned long offset, size;
	char *modname;

	if (!mm) {
		pr_err("System call from kernel thread?!\n");
		return false;
	}

	ipti = mm->context.ipti;

	/* struct unwind_state state; */

	pr_info("code: %lx reads %lx\n", regs->ip, addr);

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

	ipti->rips[ipti->rip_index++] = regs->ip;

	return true;
}

static bool ipti_is_data_access_safe(struct pt_regs *regs, unsigned long addr)
{
	/* pr_info("data: %lx reads %lx\n", regs->ip, addr); */
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
