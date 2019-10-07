// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/mmu_notifier.h>
#include <linux/page_ext.h>
#include <linux/page_idle.h>
#include <linux/page_excl.h>
#include <linux/syscalls.h>
#include <net/net_namespace.h>

#define MAX_ASS_TEST_OBJS	1024
#define TEST_ALLOC	150
#define TEST_FREE	151
#define TEST_KMALLOC	152
#define TEST_KFREE	153
#define TEST_PRINT	200
#define TEST_PRINT_ADDR	201


static int bad_address(void *p)
{
	unsigned long dummy;

	return get_kernel_nofault(dummy, (unsigned long *)p);
}

void dump_pagetable(pgd_t *pgdp, unsigned long address)
{
	pgd_t *base = pgdp;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (!base)
		base = __va(read_cr3_pa());

	pgd = base + pgd_index(address);

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

static int nr_test_objects;
static struct net *test_objects[MAX_ASS_TEST_OBJS];

static int noinline page_excl_test_page_alloc(void)
{
	struct net *new;
	struct page *page;
	const unsigned int order = sizeof(*new) >> PAGE_SHIFT;

	if (nr_test_objects >= MAX_ASS_TEST_OBJS)
		return -ENOSPC;

	page = alloc_pages(GFP_KERNEL | __GFP_EXCLUSIVE, order);
	if (!page)
		return -ENOMEM;

	new = page_address(page); /* */
	memset(new, 0xa5, sizeof(*new));

	test_objects[nr_test_objects] = new;
	nr_test_objects++;

	pr_info("==> ALLOC: %d: %d: %px (%px)\n", order, nr_test_objects, new, test_objects[nr_test_objects - 1]);

	return 0;
}

static int noinline page_excl_test_page_free(void)
{
	struct net *old;
	struct page *page;
	const unsigned int order = sizeof(*old) >> PAGE_SHIFT;
	phys_addr_t pa;
	unsigned long pfn;

	if (nr_test_objects < 1)
		return -EINVAL;

	nr_test_objects--;

	old = test_objects[nr_test_objects];
	pr_info("==> FREE: %d: %px (%px)\n", nr_test_objects, old, test_objects[nr_test_objects]);

	pa = __pa(old) - EXCLUSIVE_OFFSET;
	pfn = pa >> PAGE_SHIFT;
	page = pfn_to_page(pfn);
	__free_pages(page, order);

	return 0;
}

static int noinline page_excl_test_kmalloc(void)
{
	const unsigned int size = sizeof(struct net);
	struct net *new;

	return -EINVAL;

	if (nr_test_objects >= MAX_ASS_TEST_OBJS)
		return -ENOSPC;

	new = kmalloc(size, GFP_KERNEL_ACCOUNT | __GFP_EXCLUSIVE);
	if (!new)
		return -ENOMEM;

	memset(new, 0xa5, size);

	test_objects[nr_test_objects] = new;
	nr_test_objects++;

	pr_info("==> KMALLOC: %d: %d: %px (%px)\n", size, nr_test_objects, new, test_objects[nr_test_objects - 1]);

	return 0;
}

static int noinline page_excl_test_kfree(void)
{
	struct net *old;

	return -EINVAL;

	if (nr_test_objects < 1)
		return -EINVAL;

	nr_test_objects--;

	old = test_objects[nr_test_objects];
	pr_info("==> FREE: %d: %px (%px)\n", nr_test_objects, old, test_objects[nr_test_objects]);

	kfree(old);

	return 0;
}

static int noinline page_excl_test_print_addr(unsigned long addr)
{
	struct net *obj = (struct net *)addr;

	pr_info("==> PR: obj: %px\n", obj);
	dump_pagetable(current->mm->pgd, addr);
	pr_info("==> PR: hash_mix: %x, ifindex: %x\n", obj->hash_mix, obj->ifindex);

	return 0;
}

static int noinline page_excl_test_print(void)
{
	struct net *obj;

	if (nr_test_objects < 1)
		return -EINVAL;

	obj = test_objects[nr_test_objects - 1];

	pr_info("==> PR: obj: %px\n", obj);
	pr_info("==> PR: hash_mix: %x, ifindex: %x\n", obj->hash_mix, obj->ifindex);

	return 0;
}

static int noinline __page_excl_test(unsigned int cmd, unsigned long arg)
{
	int ret = -EINVAL;

	switch (cmd) {
	case TEST_ALLOC:
		ret = page_excl_test_page_alloc();
		break;
	case TEST_FREE:
		ret = page_excl_test_page_free();
		break;
	case TEST_KMALLOC:
		ret = page_excl_test_kmalloc();
		break;
	case TEST_KFREE:
		ret = page_excl_test_kfree();
		break;
	case TEST_PRINT:
		ret = page_excl_test_print();
		break;
	case TEST_PRINT_ADDR:
		ret = page_excl_test_print_addr(arg);
		break;
	default:
		break;
	}

	return ret;
}

SYSCALL_DEFINE2(page_excl_test, unsigned int, cmd, unsigned long, arg)
{
	return __page_excl_test(cmd, arg);
}
