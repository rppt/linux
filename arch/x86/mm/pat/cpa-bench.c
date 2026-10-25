// SPDX-License-Identifier: GPL-2.0
/* Throwaway CPA alias benchmark, included from set_memory.c */
#include <linux/debugfs.h>
#include <linux/ktime.h>
#include <linux/sort.h>

#define BENCH_RUNS	15

static int bench_cmp(const void *a, const void *b)
{
	u64 x = *(const u64 *)a, y = *(const u64 *)b;

	return x < y ? -1 : x > y;
}

enum bench_mode { B_DMAP, B_ARRAY, B_VMALLOC, B_VMALLOC_RO };
static const char * const bench_names[] = { "dmap", "array", "vmalloc", "vmalloc_ro" };

static int bench_one(enum bench_mode mode, unsigned long addr,
		     struct page **pages, int n)
{
	pgprot_t t = __pgprot(_PAGE_CPA_TEST);
	int err;

	switch (mode) {
	case B_DMAP:
	case B_VMALLOC:
		err = change_page_attr_set(&addr, n, t, 0);
		err |= change_page_attr_clear(&addr, n, t, 0);
		break;
	case B_ARRAY:
		err = cpa_set_pages_array(pages, n, t);
		err |= cpa_clear_pages_array(pages, n, t);
		break;
	case B_VMALLOC_RO:
		err = set_memory_ro(addr, n);
		err |= set_memory_rw(addr, n);
		break;
	}
	return err;
}

static void bench_run(enum bench_mode mode, int n, int loops)
{
	struct page **pages = NULL;
	struct page *page = NULL;
	unsigned long addr;
	u64 t[BENCH_RUNS];
	void *vbuf = NULL;
	int i, r, order = get_order(n * PAGE_SIZE);

	if (mode == B_VMALLOC || mode == B_VMALLOC_RO) {
		vbuf = vmalloc(n * PAGE_SIZE);
		if (!vbuf)
			return;
		addr = (unsigned long)vbuf;
	} else {
		page = alloc_pages(GFP_KERNEL, order);
		pages = kmalloc_array(n, sizeof(*pages), GFP_KERNEL);
		if (!page || !pages)
			goto out;
		for (i = 0; i < n; i++)
			pages[i] = page + i;
		addr = (unsigned long)page_address(page);
	}

	/* warm up: split the mappings */
	if (bench_one(mode, addr, pages, n)) {
		pr_err("cpa_bench: %s failed\n", bench_names[mode]);
		goto out;
	}

	for (r = 0; r < BENCH_RUNS; r++) {
		u64 start = ktime_get_ns();

		for (i = 0; i < loops; i++)
			bench_one(mode, addr, pages, n);
		t[r] = ktime_get_ns() - start;
		cond_resched();
	}
	sort(t, BENCH_RUNS, sizeof(u64), bench_cmp, NULL);
	/* ns per page per CPA call, x100 */
	pr_info("cpa_bench: %-10s n=%-4d loops=%-6d min %llu med %llu (ns/page x100)\n",
		bench_names[mode], n, loops,
		div_u64(t[0] * 100, 2ULL * loops * n),
		div_u64(t[BENCH_RUNS / 2] * 100, 2ULL * loops * n));
out:
	vfree(vbuf);
	if (page)
		__free_pages(page, order);
	kfree(pages);
}

static ssize_t cpa_bench_write(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	static const int sizes[] = { 1, 16, 512 };
	int m, s;

	for (m = 0; m < ARRAY_SIZE(bench_names); m++)
		for (s = 0; s < ARRAY_SIZE(sizes); s++)
			bench_run(m, sizes[s], 20000 / sizes[s] + 20);
	return count;
}

static const struct file_operations cpa_bench_fops = {
	.write = cpa_bench_write,
};

static int __init cpa_bench_init(void)
{
	debugfs_create_file("cpa_bench", 0200, arch_debugfs_dir, NULL,
			    &cpa_bench_fops);
	return 0;
}
late_initcall(cpa_bench_init);
