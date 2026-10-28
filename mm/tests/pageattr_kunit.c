// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for changing kernel page permissions.
 */
#include <kunit/test.h>
#include <linux/mm.h>
#include <linux/pageattr.h>
#include <linux/set_memory.h>
#include <linux/vmalloc.h>
#include <asm/tlbflush.h>

#include "../internal.h"

struct pageattr_test {
	void *area;
	unsigned long base;
};

static pgprot_t pageattr_test_apply(pgprot_t prot, enum cpa_prot op)
{
	const struct cpa_prot_op *p = &arch_cpa_prot_ops[op];

	return __pgprot((pgprot_val(prot) & ~pgprot_val(p->clr)) |
			pgprot_val(p->set));
}

static int pageattr_test_change(unsigned long addr, unsigned long numpages,
				enum cpa_prot op, unsigned int flags,
				unsigned int fail_split)
{
	struct cpa_req req = {
		.addr = addr,
		.numpages = numpages,
		.flags = flags | CPA_NO_ALIAS,
		.fail_split = fail_split,
	};

	cpa_req_add_op(&req, op);
	return cpa_change(&req);
}

static pgprot_t pageattr_test_prot(struct kunit *test, unsigned long addr)
{
	struct cpa_leaf leaf;

	KUNIT_ASSERT_EQ(test, cpa_lookup_locked(addr, &leaf), 0);
	return leaf.prot;
}

static void pageattr_test_expect_level(struct kunit *test, unsigned long addr,
				       enum pgtable_level level)
{
	struct cpa_leaf leaf;

	KUNIT_ASSERT_EQ(test, cpa_lookup_locked(addr, &leaf), 0);
	KUNIT_EXPECT_EQ_MSG(test, leaf.level, level, "addr %lx", addr);
}

/*
 * Check that the pages of [@from, @to) have @orig protections with @op
 * applied inside [@start, @end).
 */
static void pageattr_test_expect(struct kunit *test, unsigned long from,
				 unsigned long to, unsigned long start,
				 unsigned long end, pgprot_t orig,
				 enum cpa_prot op)
{
	pgprot_t changed = pageattr_test_apply(orig, op);
	unsigned long addr;

	for (addr = from; addr < to; addr += PAGE_SIZE) {
		bool inside = addr >= start && addr < end;
		pgprot_t prot = pageattr_test_prot(test, addr);

		KUNIT_EXPECT_EQ_MSG(test, pgprot_val(prot),
				    pgprot_val(inside ? changed : orig),
				    "addr %lx", addr);
	}
}

static void pageattr_test_skip_split(struct kunit *test, int err)
{
	if (err == -EOPNOTSUPP)
		kunit_skip(test, "splits are not supported");
}

/* Changes of base pages and their reverse leave the neighbours unchanged */
static void pageattr_test_pages(struct kunit *test)
{
	static const enum cpa_prot ops[][2] = {
		{ CPA_PROT_RO, CPA_PROT_RW },
		{ CPA_PROT_NP, CPA_PROT_P },
	};
	unsigned long addr, start, end;
	pgprot_t orig;
	void *area;
	int i;

	area = vmalloc(8 * PAGE_SIZE);
	KUNIT_ASSERT_NOT_NULL(test, area);
	addr = (unsigned long)area;
	start = addr + 2 * PAGE_SIZE;
	end = addr + 5 * PAGE_SIZE;
	orig = pageattr_test_prot(test, addr);

	for (i = 0; i < ARRAY_SIZE(ops); i++) {
		KUNIT_EXPECT_EQ(test, pageattr_test_change(start, 3, ops[i][0],
							   0, 0), 0);
		pageattr_test_expect(test, addr, addr + 8 * PAGE_SIZE,
				     start, end, orig, ops[i][0]);

		KUNIT_EXPECT_EQ(test, pageattr_test_change(start, 3, ops[i][1],
							   0, 0), 0);
		pageattr_test_expect(test, addr, addr + 8 * PAGE_SIZE,
				     0, 0, orig, ops[i][1]);
	}

	vfree(area);
}

/* A hole fails the request before anything is changed */
static void pageattr_test_hole(struct kunit *test)
{
	unsigned long addr;
	pgprot_t orig;
	void *area;

	area = vmalloc(2 * PAGE_SIZE);
	KUNIT_ASSERT_NOT_NULL(test, area);
	addr = (unsigned long)area;
	orig = pageattr_test_prot(test, addr);

	/* the page after the area is the guard page */
	KUNIT_EXPECT_EQ(test, pageattr_test_change(addr, 3, CPA_PROT_RO, 0, 0),
			-EFAULT);
	pageattr_test_expect(test, addr, addr + 2 * PAGE_SIZE, 0, 0, orig,
			     CPA_PROT_RO);

	vfree(area);
}

/* Aliases follow the request if the operation applies to them */
static void pageattr_test_alias(struct kunit *test)
{
	unsigned long addr, alias;
	struct cpa_req req = {};
	pgprot_t orig, alias_orig;
	struct page *page;
	void *area;

	area = vmalloc(PAGE_SIZE);
	KUNIT_ASSERT_NOT_NULL(test, area);
	addr = (unsigned long)area;
	page = vmalloc_to_page(area);
	if (PageHighMem(page)) {
		vfree(area);
		kunit_skip(test, "no direct map alias");
	}

	alias = (unsigned long)page_address(page);
	orig = pageattr_test_prot(test, addr);
	alias_orig = pageattr_test_prot(test, alias);

	req.addr = addr;
	req.numpages = 1;
	cpa_req_add_op(&req, CPA_PROT_RO);
	KUNIT_EXPECT_EQ(test, cpa_change(&req), 0);
	pageattr_test_expect(test, addr, addr + PAGE_SIZE, addr,
			     addr + PAGE_SIZE, orig, CPA_PROT_RO);
	if (arch_cpa_prot_ops[CPA_PROT_RO].alias)
		pageattr_test_expect(test, alias, alias + PAGE_SIZE, alias,
				     alias + PAGE_SIZE, alias_orig,
				     CPA_PROT_RO);
	else
		KUNIT_EXPECT_EQ(test, pgprot_val(alias_orig),
				pgprot_val(pageattr_test_prot(test, alias)));

	KUNIT_EXPECT_EQ(test, set_memory_rw(addr, 1), 0);
	KUNIT_EXPECT_EQ(test, pgprot_val(orig),
			pgprot_val(pageattr_test_prot(test, addr)));
	KUNIT_EXPECT_EQ(test, pgprot_val(alias_orig),
			pgprot_val(pageattr_test_prot(test, alias)));

	vfree(area);
}

#ifdef CONFIG_ARCH_HAS_SET_DIRECT_MAP
static void pageattr_test_present(struct kunit *test)
{
	struct page *page;
	unsigned long addr;

	if (!can_set_direct_map())
		kunit_skip(test, "the direct map cannot be changed");

	page = alloc_page(GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, page);
	addr = (unsigned long)page_address(page);

	KUNIT_EXPECT_TRUE(test, kernel_page_present(page));
	KUNIT_EXPECT_EQ(test, set_direct_map_invalid_noflush(page, 1), 0);
	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
	KUNIT_EXPECT_FALSE(test, kernel_page_present(page));
	KUNIT_EXPECT_EQ(test, set_direct_map_default_noflush(page, 1), 0);
	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
	KUNIT_EXPECT_TRUE(test, kernel_page_present(page));

	__free_page(page);
}
#endif

static int pageattr_test_init(struct kunit *test)
{
	struct pageattr_test *t;
	struct cpa_leaf leaf;
	unsigned long addr;
	int i;

	t = kunit_kzalloc(test, sizeof(*t), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, t);
	test->priv = t;

	/* tests that use large leaves need three of them in a row */
	t->area = vmalloc_huge(4 * PMD_SIZE, GFP_KERNEL);
	if (!t->area)
		return 0;

	t->base = ALIGN((unsigned long)t->area, PMD_SIZE);
	for (i = 0; i < 3; i++) {
		addr = t->base + i * PMD_SIZE;
		if (cpa_lookup_locked(addr, &leaf) ||
		    leaf.level != PGTABLE_LEVEL_PMD || leaf.nr != 1) {
			t->base = 0;
			break;
		}
	}

	return 0;
}

static void pageattr_test_exit(struct kunit *test)
{
	struct pageattr_test *t = test->priv;

	if (t)
		vfree(t->area);
}

static unsigned long pageattr_test_base(struct kunit *test)
{
	struct pageattr_test *t = test->priv;

	if (!t->base)
		kunit_skip(test, "no PMD leaves in vmalloc");

	return t->base;
}

/* A change of an entire large leaf does not split it */
static void pageattr_test_leaf(struct kunit *test)
{
	unsigned long base = pageattr_test_base(test);
	unsigned long nr = PMD_SIZE >> PAGE_SHIFT;
	pgprot_t orig = pageattr_test_prot(test, base);

	KUNIT_EXPECT_EQ(test, pageattr_test_change(base, nr, CPA_PROT_RO, 0, 0),
			0);
	pageattr_test_expect_level(test, base, PGTABLE_LEVEL_PMD);
	pageattr_test_expect(test, base, base + PMD_SIZE, base,
			     base + PMD_SIZE, orig, CPA_PROT_RO);

	KUNIT_EXPECT_EQ(test, pageattr_test_change(base, nr, CPA_PROT_RW, 0, 0),
			0);
	pageattr_test_expect_level(test, base, PGTABLE_LEVEL_PMD);
	pageattr_test_expect(test, base, base + PMD_SIZE, 0, 0, orig,
			     CPA_PROT_RW);
}

/* A partial change splits a large leaf */
static void pageattr_test_split_partial(struct kunit *test)
{
	unsigned long base = pageattr_test_base(test);
	unsigned long addr = base + PMD_SIZE / 2;
	pgprot_t orig = pageattr_test_prot(test, base);
	int err;

	err = pageattr_test_change(addr, 1, CPA_PROT_RO, 0, 0);
	pageattr_test_skip_split(test, err);
	KUNIT_EXPECT_EQ(test, err, 0);
	pageattr_test_expect_level(test, addr, PGTABLE_LEVEL_PTE);
	pageattr_test_expect(test, base, base + PMD_SIZE, addr,
			     addr + PAGE_SIZE, orig, CPA_PROT_RO);

	KUNIT_EXPECT_EQ(test, pageattr_test_change(addr, 1, CPA_PROT_RW, 0, 0),
			0);
	pageattr_test_expect(test, base, base + PMD_SIZE, 0, 0, orig,
			     CPA_PROT_RW);
}

/* CPA_SPLIT splits leaves without changing permissions */
static void pageattr_test_split(struct kunit *test)
{
	unsigned long base = pageattr_test_base(test);
	unsigned long nr = PMD_SIZE >> PAGE_SHIFT;
	struct cpa_leaf before, after;
	unsigned long addr;
	int err;
	struct cpa_req req = {
		.addr = base,
		.numpages = nr,
		.flags = CPA_SPLIT | CPA_NO_ALIAS,
	};

	KUNIT_ASSERT_EQ(test, cpa_lookup_locked(base, &before), 0);
	err = cpa_change(&req);
	pageattr_test_skip_split(test, err);
	KUNIT_EXPECT_EQ(test, err, 0);

	for (addr = base; addr < base + PMD_SIZE; addr += PAGE_SIZE) {
		KUNIT_ASSERT_EQ(test, cpa_lookup_locked(addr, &after), 0);
		KUNIT_EXPECT_EQ(test, after.level, PGTABLE_LEVEL_PTE);
		KUNIT_EXPECT_EQ(test, after.nr, 1);
		KUNIT_EXPECT_EQ(test, after.pfn,
				before.pfn + ((addr - base) >> PAGE_SHIFT));
		KUNIT_EXPECT_EQ(test, pgprot_val(after.prot),
				pgprot_val(before.prot));
	}
}

/* A request that fails on the Nth split leaves the permissions unchanged */
static void pageattr_test_rollback(struct kunit *test)
{
	unsigned long base = pageattr_test_base(test);
	unsigned long start = base + PAGE_SIZE;
	unsigned long end = base + 2 * PMD_SIZE + PAGE_SIZE;
	unsigned long nr = (end - start) >> PAGE_SHIFT;
	pgprot_t orig = pageattr_test_prot(test, base);
	int n, err;

	for (n = 1; ; n++) {
		err = pageattr_test_change(start, nr, CPA_PROT_RO, 0, n);
		if (!err)
			break;

		pageattr_test_skip_split(test, err);
		KUNIT_ASSERT_EQ(test, err, -ENOMEM);
		pageattr_test_expect(test, base, base + 3 * PMD_SIZE, 0, 0,
				     orig, CPA_PROT_RO);
	}

	/* both ends of the range must be split */
	KUNIT_EXPECT_GT(test, n, 2);
	pageattr_test_expect(test, base, base + 3 * PMD_SIZE, start, end, orig,
			     CPA_PROT_RO);

	KUNIT_EXPECT_EQ(test, pageattr_test_change(start, nr, CPA_PROT_RW, 0, 0),
			0);
	pageattr_test_expect(test, base, base + 3 * PMD_SIZE, 0, 0, orig,
			     CPA_PROT_RW);
}

static void pageattr_test_random(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, cpa_random_test(false), 0);
}

static struct kunit_case pageattr_test_cases[] = {
	KUNIT_CASE(pageattr_test_pages),
	KUNIT_CASE(pageattr_test_hole),
	KUNIT_CASE(pageattr_test_alias),
#ifdef CONFIG_ARCH_HAS_SET_DIRECT_MAP
	KUNIT_CASE(pageattr_test_present),
#endif
	KUNIT_CASE(pageattr_test_leaf),
	KUNIT_CASE(pageattr_test_split_partial),
	KUNIT_CASE(pageattr_test_split),
	KUNIT_CASE(pageattr_test_rollback),
	KUNIT_CASE(pageattr_test_random),
	{}
};

static struct kunit_suite pageattr_test_suite = {
	.name = "pageattr",
	.init = pageattr_test_init,
	.exit = pageattr_test_exit,
	.test_cases = pageattr_test_cases,
};
kunit_test_suite(pageattr_test_suite);
