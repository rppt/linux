// SPDX-License-Identifier: GPL-2.0
/*
 * Self test for changing kernel page permissions.
 *
 * Based on arch/x86/mm/pat/cpa-test.c.
 *
 * Sets a software bit on random ranges in the direct map and in a vmalloc
 * area, verifies that the bit is set exactly in these ranges, then clears
 * the bit and verifies that the page tables are restored.
 */
#include <linux/bitmap.h>
#include <linux/kthread.h>
#include <linux/memblock.h>
#include <linux/random.h>
#include <linux/sizes.h>
#include <linux/vmalloc.h>

enum {
	CPA_TEST_NR		= 100,
	CPA_TEST_MAX_PAGES	= 100,
	CPA_TEST_AREA_SIZE	= SZ_8M,
};

struct cpa_test_range {
	unsigned long addr;
	unsigned long npages;
	unsigned long pfn;
	enum pgtable_level level;
};

static struct cpa_test_range cpa_test_ranges[CPA_TEST_NR];

/* Only print the results of the first pass */
static bool cpa_test_print = true;

static int cpa_test_change(struct cpa_test_range *r, bool set,
			   unsigned int flags)
{
	struct cpa_req req = {
		.addr = r->addr,
		.numpages = r->npages,
		.flags = flags | CPA_NO_ALIAS,
	};

	if (set)
		req.set = arch_cpa_test_prot();
	else
		req.clr = arch_cpa_test_prot();

	return cpa_change(&req);
}

/*
 * Check that the test bit is @set in the pages of @r, that it is not set in
 * the pages around @r and that the pfns did not change.
 */
static int cpa_test_check(struct cpa_test_range *r, bool set)
{
	unsigned long test = pgprot_val(arch_cpa_test_prot());
	unsigned long end = r->addr + r->npages * PAGE_SIZE;
	struct cpa_leaf leaf;
	unsigned long addr;
	int failed = 0;

	guard(mutex)(&cpa_mutex);

	for (addr = r->addr - PAGE_SIZE; addr <= end; addr += PAGE_SIZE) {
		bool inside = addr >= r->addr && addr < end;
		unsigned long pfn;

		if (cpa_lookup(addr, &leaf)) {
			if (inside) {
				pr_err("CPA %lx: not mapped\n", addr);
				failed++;
			}
			continue;
		}

		if (!!(pgprot_val(leaf.prot) & test) != (inside && set)) {
			pr_err("CPA %lx: test bit is %s\n", addr,
			       pgprot_val(leaf.prot) & test ? "set" : "clear");
			failed++;
		}

		pfn = leaf.pfn + ((addr - leaf.start) >> PAGE_SHIFT);
		if (inside && pfn != r->pfn + ((addr - r->addr) >> PAGE_SHIFT)) {
			pr_err("CPA %lx: pfn %lx changed\n", addr, pfn);
			failed++;
		}
	}

	return failed;
}

/*
 * Pick up to CPA_TEST_NR random ranges of pages inside [@start, @end) that
 * neither overlap nor touch each other.
 */
static int cpa_test_pick(unsigned long start, unsigned long end)
{
	unsigned long nr_pages = (end - start) >> PAGE_SHIFT;
	unsigned long *used;
	struct cpa_leaf leaf;
	int i, nr = 0;

	used = bitmap_zalloc(nr_pages, GFP_KERNEL);
	if (!used)
		return -ENOMEM;

	guard(mutex)(&cpa_mutex);

	for (i = 0; i < CPA_TEST_NR; i++) {
		struct cpa_test_range *r = &cpa_test_ranges[nr];
		unsigned long idx = get_random_u32_below(nr_pages - 2) + 1;
		unsigned long npages = get_random_u32_below(CPA_TEST_MAX_PAGES) + 1;
		unsigned long k;

		npages = min(npages, nr_pages - idx - 1);
		for (k = 0; k < npages; k++) {
			unsigned long addr = start + (idx + k) * PAGE_SIZE;

			if (test_bit(idx + k, used) || cpa_lookup(addr, &leaf))
				break;
			if (!k) {
				r->pfn = leaf.pfn +
					 ((addr - leaf.start) >> PAGE_SHIFT);
				r->level = leaf.level;
			}
		}
		if (!k)
			continue;

		r->addr = start + idx * PAGE_SIZE;
		r->npages = k;
		bitmap_set(used, idx - 1, k + 2);
		nr++;
	}

	bitmap_free(used);
	return nr;
}

static int cpa_test_area(const char *name, unsigned long start,
			 unsigned long end, unsigned int flags, bool collapse)
{
	struct cpa_req req = {
		.addr = start,
		.numpages = (end - start) >> PAGE_SHIFT,
		.flags = flags,
	};
	int failed = 0, collapsed = 0;
	struct cpa_leaf leaf;
	int i, nr, err;

	if (arch_cpa_check_range(&req))
		return 0;

	nr = cpa_test_pick(start, end);
	if (nr < 0)
		return nr;

	for (i = 0; i < nr; i++) {
		err = cpa_test_change(&cpa_test_ranges[i], true, flags);
		/* the architecture cannot split the leaves of this range */
		if (err == -EOPNOTSUPP) {
			cpa_test_ranges[i].npages = 0;
		} else if (err) {
			pr_err("CPA %lx: set failed: %d\n",
			       cpa_test_ranges[i].addr, err);
			failed++;
		}
	}

	for (i = 0; i < nr; i++)
		failed += cpa_test_check(&cpa_test_ranges[i], true);

	for (i = 0; i < nr; i++) {
		err = cpa_test_change(&cpa_test_ranges[i], false, flags);
		if (err) {
			pr_err("CPA %lx: clear failed: %d\n",
			       cpa_test_ranges[i].addr, err);
			failed++;
		}
	}

	for (i = 0; i < nr; i++) {
		struct cpa_test_range *r = &cpa_test_ranges[i];

		failed += cpa_test_check(r, false);

		guard(mutex)(&cpa_mutex);
		if (cpa_lookup(r->addr, &leaf) || leaf.level >= r->level) {
			collapsed++;
			continue;
		}

		if (collapse && arch_cpa_can_collapse(&req, r->level)) {
			pr_err("CPA %lx: level %d was not restored, now %d\n",
			       r->addr, r->level, leaf.level);
			failed++;
		}
	}

	if (cpa_test_print)
		pr_info("CPA self-test: %s: %d ranges, %d restored, %d failures\n",
			name, nr, collapsed, failed);

	return failed;
}

static int cpa_test_direct_map(void)
{
	unsigned long start = (unsigned long)__va(PFN_PHYS(min_low_pfn));
	unsigned long end = (unsigned long)__va(PFN_PHYS(max_low_pfn));

	if (!IS_ENABLED(CONFIG_ARCH_HAS_SET_DIRECT_MAP))
		return 0;

	/* other users may split the direct map at any time */
	return cpa_test_area("direct map", start, end, 0, false);
}

static int cpa_test_vmalloc(void)
{
	void *area;
	int failed;

	area = vmalloc_huge(CPA_TEST_AREA_SIZE, GFP_KERNEL);
	if (!area)
		return -ENOMEM;

	/* the area is not shared, it can be collapsed */
	failed = cpa_test_area("vmalloc", (unsigned long)area,
			       (unsigned long)area + CPA_TEST_AREA_SIZE,
			       CPA_COLLAPSE, !debug_pagealloc_enabled());
	vfree(area);

	return failed;
}

static int cpa_test(void)
{
	int failed = 0, err;

	err = cpa_test_direct_map();
	if (err < 0)
		return err;
	failed += err;

	err = cpa_test_vmalloc();
	if (err < 0)
		return err;
	failed += err;

	if (failed) {
		WARN(1, "CPA self-test: NOT PASSED. Please report.\n");
		return -EINVAL;
	}

	if (cpa_test_print)
		pr_info("CPA self-test: ok\n");

	return 0;
}

static int cpa_test_thread(void *unused)
{
	while (!kthread_should_stop()) {
		schedule_timeout_interruptible(HZ * 30);
		if (cpa_test() < 0)
			break;
		cpa_test_print = false;
	}

	return 0;
}

static int __init cpa_test_init(void)
{
	struct task_struct *p;

	if (!pgprot_val(arch_cpa_test_prot()))
		return 0;

	p = kthread_run(cpa_test_thread, NULL, "pageattr-test");
	WARN_ON(IS_ERR(p));

	return 0;
}
late_initcall(cpa_test_init);
