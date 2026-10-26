// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for changing kernel page permissions.
 *
 * Included from mm/pageattr.c to access the page table walker.
 */
#include <kunit/test.h>
#include <linux/vmalloc.h>

struct pageattr_test {
	void *area;
	unsigned long base;
	unsigned long size;
};

static int pageattr_test_lookup(unsigned long addr, struct cpa_leaf *leaf)
{
	guard(mutex)(&cpa_mutex);
	return cpa_lookup(addr, leaf);
}

static int pageattr_test_change(unsigned long addr, unsigned long numpages,
				bool set, unsigned int flags)
{
	struct cpa_req req = {
		.addr = addr,
		.numpages = numpages,
		.flags = flags | CPA_NO_ALIAS,
	};

	if (set)
		req.set = arch_cpa_test_prot();
	else
		req.clr = arch_cpa_test_prot();

	return cpa_change(&req);
}

static void pageattr_test_skip_split(struct kunit *test, int err)
{
	if (err == -EOPNOTSUPP)
		kunit_skip(test, "splits are not supported");
}

static bool pageattr_test_can_collapse(void)
{
	struct cpa_req req = { .flags = CPA_COLLAPSE };

	return !debug_pagealloc_enabled() &&
	       arch_cpa_can_collapse(&req, PGTABLE_LEVEL_PMD);
}

/* Check that the test bit is @set exactly in [@start, @end) */
static void pageattr_test_expect(struct kunit *test, unsigned long from,
				 unsigned long to, unsigned long start,
				 unsigned long end, bool set)
{
	unsigned long bit = pgprot_val(arch_cpa_test_prot());
	struct cpa_leaf leaf;
	unsigned long addr;

	for (addr = from; addr < to; addr += PAGE_SIZE) {
		bool inside = addr >= start && addr < end;

		KUNIT_ASSERT_EQ(test, pageattr_test_lookup(addr, &leaf), 0);
		KUNIT_EXPECT_EQ_MSG(test, !!(pgprot_val(leaf.prot) & bit),
				    inside && set, "addr %lx", addr);
	}
}

static void pageattr_test_expect_level(struct kunit *test, unsigned long addr,
				       enum pgtable_level level)
{
	struct cpa_leaf leaf;

	KUNIT_ASSERT_EQ(test, pageattr_test_lookup(addr, &leaf), 0);
	KUNIT_EXPECT_EQ_MSG(test, leaf.level, level, "addr %lx", addr);
}

/* Changes of base pages and unchanged neighbours */
static void pageattr_test_pages(struct kunit *test)
{
	unsigned long addr;
	void *area;

	area = vmalloc(8 * PAGE_SIZE);
	KUNIT_ASSERT_NOT_NULL(test, area);
	addr = (unsigned long)area;

	KUNIT_EXPECT_EQ(test, pageattr_test_change(addr + 2 * PAGE_SIZE, 3,
						   true, 0), 0);
	pageattr_test_expect(test, addr, addr + 8 * PAGE_SIZE,
			     addr + 2 * PAGE_SIZE, addr + 5 * PAGE_SIZE, true);

	KUNIT_EXPECT_EQ(test, pageattr_test_change(addr + 2 * PAGE_SIZE, 3,
						   false, 0), 0);
	pageattr_test_expect(test, addr, addr + 8 * PAGE_SIZE, 0, 0, false);

	vfree(area);
}

/* A hole fails the request before anything is changed */
static void pageattr_test_hole(struct kunit *test)
{
	unsigned long addr;
	void *area;

	area = vmalloc(2 * PAGE_SIZE);
	KUNIT_ASSERT_NOT_NULL(test, area);
	addr = (unsigned long)area;

	/* the page after the area is the guard page */
	KUNIT_EXPECT_LT(test, pageattr_test_change(addr, 3, true, 0), 0);
	pageattr_test_expect(test, addr, addr + 2 * PAGE_SIZE, 0, 0, false);

	vfree(area);
}

static int pageattr_test_init(struct kunit *test)
{
	struct pageattr_test *t;
	unsigned long addr;
	int i;

	if (!pgprot_val(arch_cpa_test_prot()))
		kunit_skip(test, "no software bit for the test");

	t = kunit_kzalloc(test, sizeof(*t), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, t);
	test->priv = t;

	/* tests that use large leaves need three of them in a row */
	t->size = 4 * PMD_SIZE;
	t->area = vmalloc_huge(t->size, GFP_KERNEL);
	if (!t->area)
		return 0;

	t->base = ALIGN((unsigned long)t->area, PMD_SIZE);
	for (i = 0; i < 3; i++) {
		struct cpa_leaf leaf;

		addr = t->base + i * PMD_SIZE;
		if (pageattr_test_lookup(addr, &leaf) ||
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
	cpa_fail_split = 0;
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

	KUNIT_EXPECT_EQ(test, pageattr_test_change(base, nr, true, 0), 0);
	pageattr_test_expect_level(test, base, PGTABLE_LEVEL_PMD);
	pageattr_test_expect(test, base, base + PMD_SIZE, base,
			     base + PMD_SIZE, true);

	KUNIT_EXPECT_EQ(test, pageattr_test_change(base, nr, false, 0), 0);
	pageattr_test_expect_level(test, base, PGTABLE_LEVEL_PMD);
}

/* A partial change splits a large leaf and reverting it collapses it */
static void pageattr_test_split_collapse(struct kunit *test)
{
	unsigned long base = pageattr_test_base(test);
	unsigned long addr = base + PMD_SIZE / 2;
	int err;

	err = pageattr_test_change(addr, 1, true, CPA_COLLAPSE);
	pageattr_test_skip_split(test, err);
	KUNIT_EXPECT_EQ(test, err, 0);
	pageattr_test_expect_level(test, addr, PGTABLE_LEVEL_PTE);
	pageattr_test_expect(test, base, base + PMD_SIZE, addr,
			     addr + PAGE_SIZE, true);

	KUNIT_EXPECT_EQ(test, pageattr_test_change(addr, 1, false,
						   CPA_COLLAPSE), 0);
	pageattr_test_expect(test, base, base + PMD_SIZE, 0, 0, false);
	if (pageattr_test_can_collapse())
		pageattr_test_expect_level(test, base, PGTABLE_LEVEL_PMD);
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

	KUNIT_ASSERT_EQ(test, pageattr_test_lookup(base, &before), 0);
	err = cpa_change(&req);
	pageattr_test_skip_split(test, err);
	KUNIT_EXPECT_EQ(test, err, 0);

	for (addr = base; addr < base + PMD_SIZE; addr += PAGE_SIZE) {
		KUNIT_ASSERT_EQ(test, pageattr_test_lookup(addr, &after), 0);
		KUNIT_EXPECT_EQ(test, after.level, PGTABLE_LEVEL_PTE);
		KUNIT_EXPECT_EQ(test, after.nr, 1);
		KUNIT_EXPECT_EQ(test, after.pfn,
				before.pfn + ((addr - base) >> PAGE_SHIFT));
		KUNIT_EXPECT_EQ(test, pgprot_val(after.prot),
				pgprot_val(before.prot));
	}
}

/*
 * A request that fails on the Nth split leaves the permissions unchanged
 * and restores the large leaves split before the failure.
 */
static void pageattr_test_rollback(struct kunit *test)
{
	unsigned long base = pageattr_test_base(test);
	unsigned long start = base + PAGE_SIZE;
	unsigned long end = base + 2 * PMD_SIZE + PAGE_SIZE;
	unsigned long nr = (end - start) >> PAGE_SHIFT;
	int n, err;

	for (n = 1; ; n++) {
		cpa_fail_split = n;
		err = pageattr_test_change(start, nr, true, CPA_COLLAPSE);
		cpa_fail_split = 0;
		if (!err)
			break;

		pageattr_test_skip_split(test, err);
		KUNIT_ASSERT_EQ(test, err, -ENOMEM);
		pageattr_test_expect(test, base, base + 3 * PMD_SIZE, 0, 0,
				     false);
		if (pageattr_test_can_collapse()) {
			pageattr_test_expect_level(test, base,
						   PGTABLE_LEVEL_PMD);
			pageattr_test_expect_level(test, base + 2 * PMD_SIZE,
						   PGTABLE_LEVEL_PMD);
		}
	}

	/* both ends of the range must be split */
	KUNIT_EXPECT_GT(test, n, 2);
	pageattr_test_expect(test, base, base + 3 * PMD_SIZE, start, end, true);

	KUNIT_EXPECT_EQ(test, pageattr_test_change(start, nr, false,
						   CPA_COLLAPSE), 0);
	pageattr_test_expect(test, base, base + 3 * PMD_SIZE, 0, 0, false);
}

static struct kunit_case pageattr_test_cases[] = {
	KUNIT_CASE(pageattr_test_pages),
	KUNIT_CASE(pageattr_test_hole),
	KUNIT_CASE(pageattr_test_leaf),
	KUNIT_CASE(pageattr_test_split_collapse),
	KUNIT_CASE(pageattr_test_split),
	KUNIT_CASE(pageattr_test_rollback),
	{}
};

static struct kunit_suite pageattr_test_suite = {
	.name = "pageattr",
	.init = pageattr_test_init,
	.exit = pageattr_test_exit,
	.test_cases = pageattr_test_cases,
};
kunit_test_suite(pageattr_test_suite);
