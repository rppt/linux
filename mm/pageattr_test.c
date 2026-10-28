// SPDX-License-Identifier: GPL-2.0
/*
 * Random test for changing kernel page permissions.
 *
 * Changes permissions of random ranges in a vmalloc area and in a part of
 * the direct map owned by the test, verifies the page tables against
 * arch_cpa_prot_ops[] and restores the original permissions.
 */
#include <linux/gfp.h>
#include <linux/kthread.h>
#include <linux/mm.h>
#include <linux/pageattr.h>
#include <linux/random.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include "internal.h"

#define CPA_TEST_ITERATIONS	200
#define CPA_TEST_AREA_SIZE	SZ_8M
#define CPA_TEST_ORDER		min(MAX_PAGE_ORDER, get_order(SZ_4M))

#define CPA_TEST_RO		BIT(0)
#define CPA_TEST_NP		BIT(1)

static const struct {
	enum cpa_prot op;
	u8 state;
	bool set;
} cpa_test_ops[] = {
	{ CPA_PROT_RO, CPA_TEST_RO, true },
	{ CPA_PROT_RW, CPA_TEST_RO, false },
	{ CPA_PROT_NP, CPA_TEST_NP, true },
	{ CPA_PROT_P, CPA_TEST_NP, false },
};

struct cpa_test_page {
	unsigned long pfn;
	pgprot_t prot;
	u8 state;
};

static pgprot_t cpa_test_apply(pgprot_t prot, enum cpa_prot op)
{
	const struct cpa_prot_op *p = &arch_cpa_prot_ops[op];

	return __pgprot((pgprot_val(prot) & ~pgprot_val(p->clr)) |
			pgprot_val(p->set));
}

static int cpa_test_change(unsigned long addr, unsigned long numpages,
			   enum cpa_prot op)
{
	struct cpa_req req = {
		.addr = addr,
		.numpages = numpages,
		.flags = CPA_NO_ALIAS,
	};

	cpa_req_add_op(&req, op);
	return cpa_change(&req);
}

static pgprot_t cpa_test_expected(struct cpa_test_page *page)
{
	pgprot_t prot = page->prot;

	prot = cpa_test_apply(prot, page->state & CPA_TEST_RO ?
				    CPA_PROT_RO : CPA_PROT_RW);
	return cpa_test_apply(prot, page->state & CPA_TEST_NP ?
				    CPA_PROT_NP : CPA_PROT_P);
}

/* Check the pages of [@start, @start + @nr pages), @orig checks the restore */
static int cpa_test_check(unsigned long start, struct cpa_test_page *pages,
			  unsigned long nr, bool orig)
{
	struct cpa_leaf leaf;
	unsigned long i, addr, pfn;
	pgprot_t prot;
	int failed = 0;

	for (i = 0; i < nr; i++) {
		addr = start + i * PAGE_SIZE;
		if (cpa_lookup_locked(addr, &leaf)) {
			pr_err("CPA %lx: not mapped\n", addr);
			failed++;
			continue;
		}

		pfn = leaf.pfn + ((addr - leaf.start) >> PAGE_SHIFT);
		prot = orig ? pages[i].prot : cpa_test_expected(&pages[i]);
		if (pfn == pages[i].pfn &&
		    pgprot_val(leaf.prot) == pgprot_val(prot))
			continue;

		pr_err("CPA %lx: pfn %lx prot %llx, expected pfn %lx prot %llx\n",
		       addr, pfn, (u64)pgprot_val(leaf.prot), pages[i].pfn,
		       (u64)pgprot_val(prot));
		failed++;
	}

	return failed;
}

static void cpa_test_random_change(unsigned long start,
				   struct cpa_test_page *pages,
				   unsigned long nr, int *failed)
{
	unsigned int idx = get_random_u32_below(ARRAY_SIZE(cpa_test_ops));
	unsigned long first = get_random_u32_below(nr);
	unsigned long len = get_random_u32_below(min(nr - first, nr / 4)) + 1;
	unsigned long i;
	int err;

	err = cpa_test_change(start + first * PAGE_SIZE, len,
			      cpa_test_ops[idx].op);
	/* the architecture cannot split the leaves of this range */
	if (err == -EOPNOTSUPP)
		return;
	if (err) {
		pr_err("CPA %lx: change failed: %d\n",
		       start + first * PAGE_SIZE, err);
		(*failed)++;
		return;
	}

	for (i = first; i < first + len; i++) {
		if (cpa_test_ops[idx].set)
			pages[i].state |= cpa_test_ops[idx].state;
		else
			pages[i].state &= ~cpa_test_ops[idx].state;
	}
}

static int cpa_test_area(const char *name, unsigned long start,
			 unsigned long nr, bool verbose)
{
	struct cpa_test_page *pages;
	struct cpa_leaf leaf;
	unsigned long i;
	int failed = 0;

	/* the architecture does not change permissions of this area */
	if (cpa_test_change(start, nr, CPA_PROT_RW) == -EINVAL)
		return 0;

	pages = kvcalloc(nr, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	for (i = 0; i < nr; i++) {
		unsigned long addr = start + i * PAGE_SIZE;

		if (cpa_lookup_locked(addr, &leaf)) {
			kvfree(pages);
			return -EFAULT;
		}
		pages[i].pfn = leaf.pfn + ((addr - leaf.start) >> PAGE_SHIFT);
		pages[i].prot = leaf.prot;
	}

	for (i = 0; i < CPA_TEST_ITERATIONS; i++)
		cpa_test_random_change(start, pages, nr, &failed);

	failed += cpa_test_check(start, pages, nr, false);

	if (cpa_test_change(start, nr, CPA_PROT_RW) ||
	    cpa_test_change(start, nr, CPA_PROT_P)) {
		pr_err("CPA %s: restore failed\n", name);
		failed++;
	}
	failed += cpa_test_check(start, pages, nr, true);

	if (verbose)
		pr_info("CPA self-test: %s: %d failures\n", name, failed);

	kvfree(pages);
	return failed;
}

/**
 * cpa_random_test - change permissions of random ranges and verify them
 * @verbose: print the results
 *
 * Return: the number of failures or a negative error code.
 */
int cpa_random_test(bool verbose)
{
	struct page *page;
	int failed, err;
	void *area;

	area = vmalloc_huge(CPA_TEST_AREA_SIZE, GFP_KERNEL);
	if (!area)
		return -ENOMEM;

	failed = cpa_test_area("vmalloc", (unsigned long)area,
			       CPA_TEST_AREA_SIZE >> PAGE_SHIFT, verbose);
	vfree(area);
	if (failed < 0)
		return failed;

	page = alloc_pages(GFP_KERNEL, CPA_TEST_ORDER);
	if (!page)
		return -ENOMEM;

	err = cpa_test_area("direct map", (unsigned long)page_address(page),
			    1UL << CPA_TEST_ORDER, verbose);
	__free_pages(page, CPA_TEST_ORDER);
	if (err < 0)
		return err;

	return failed + err;
}

#ifdef CONFIG_DEBUG_PAGEATTR
static int cpa_test_thread(void *unused)
{
	bool verbose = true;
	int ret;

	while (!kthread_should_stop()) {
		schedule_timeout_interruptible(HZ * 30);

		ret = cpa_random_test(verbose);
		if (ret) {
			WARN(ret > 0, "CPA self-test: NOT PASSED. Please report.\n");
			break;
		}
		if (verbose)
			pr_info("CPA self-test: ok\n");
		verbose = false;
	}

	return 0;
}

static int __init cpa_test_init(void)
{
	struct task_struct *p;

	p = kthread_run(cpa_test_thread, NULL, "pageattr-test");
	WARN_ON(IS_ERR(p));

	return 0;
}
late_initcall(cpa_test_init);
#endif /* CONFIG_DEBUG_PAGEATTR */
