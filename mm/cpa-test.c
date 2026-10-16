// SPDX-License-Identifier: GPL-2.0
/*
 * self test for change_page_attr.
 *
 * Clears the a test pte bit on random pages in the direct mapping,
 * then reverts and compares page tables forwards and afterwards.
 */
#include <linux/memblock.h>
#include <linux/kthread.h>
#include <linux/random.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/pageattr.h>
#include <linux/pgtable.h>
#include <linux/vmalloc.h>

/*
 * Only print the results of the first pass:
 */
static __read_mostly int print = 1;
static unsigned long min_test_pfn;
static unsigned long max_test_pfn;

enum {
	NTEST			= 3 * 100,
	NPAGES			= 100,
};

#define LPS	PMD_SIZE
#define GPS	PUD_SIZE
#define HPS	P4D_SIZE

static int pte_testbit(pte_t pte)
{
	return !!(pte_val(pte) & pgprot_val(ARCH_PAGE_CPA_TEST));
}

struct cpa_test_leaf {
	pte_t pte;
	enum pgtable_level level;
};

static int cpa_test_lookup(unsigned long addr, struct cpa_test_leaf *leaf)
{
	pgd_t *pgdp = pgd_offset_k(addr);
	p4d_t *p4dp, p4d;
	pud_t *pudp, pud;
	pmd_t *pmdp, pmd;

	if (pgd_none(pgdp_get(pgdp)))
		return -ENOENT;

	p4dp = p4d_offset(pgdp, addr);
	p4d = p4dp_get(p4dp);
	if (p4d_none(p4d))
		return -ENOENT;
	if (p4d_leaf(p4d) || !p4d_present(p4d)) {
		leaf->pte = __pte(p4d_val(p4d));
		leaf->level = PGTABLE_LEVEL_P4D;
		return 0;
	}

	pudp = pud_offset(p4dp, addr);
	pud = pudp_get(pudp);
	if (pud_none(pud))
		return -ENOENT;
	if (pud_leaf(pud) || !pud_present(pud)) {
		leaf->pte = __pte(pud_val(pud));
		leaf->level = PGTABLE_LEVEL_PUD;
		return 0;
	}

	pmdp = pmd_offset(pudp, addr);
	pmd = pmdp_get(pmdp);
	if (pmd_none(pmd))
		return -ENOENT;
	if (pmd_leaf(pmd) || !pmd_present(pmd)) {
		leaf->pte = __pte(pmd_val(pmd));
		leaf->level = PGTABLE_LEVEL_PMD;
		return 0;
	}

	leaf->pte = ptep_get(pte_offset_kernel(pmdp, addr));
	leaf->level = PGTABLE_LEVEL_PTE;

	return pte_none(leaf->pte) ? -ENOENT : 0;
}

struct split_state {
	long hpg, lpg, gpg, spg, exec;
	long min_exec, max_exec;
};

static int print_split(struct split_state *s)
{
	long i, expected, missed = 0;

	s->hpg = s->lpg = s->gpg = s->spg = s->exec = 0;
	s->min_exec = ~0UL;
	s->max_exec = 0;
	for (i = min_test_pfn; i < max_test_pfn; ) {
		unsigned long addr = (unsigned long)__va(i << PAGE_SHIFT);
		struct cpa_test_leaf leaf;

		if (cpa_test_lookup(addr, &leaf)) {
			missed++;
			i++;
			continue;
		}

		if (leaf.level == PGTABLE_LEVEL_P4D) {
			s->hpg++;
			i += HPS/PAGE_SIZE;
		} else if (leaf.level == PGTABLE_LEVEL_PUD) {
			s->gpg++;
			i += GPS/PAGE_SIZE;
		} else if (leaf.level == PGTABLE_LEVEL_PMD) {
			s->lpg++;
			i += LPS/PAGE_SIZE;
		} else {
			s->spg++;
			i++;
		}
		if (pte_exec(leaf.pte)) {
			s->exec++;
			if (addr < s->min_exec)
				s->min_exec = addr;
			if (addr > s->max_exec)
				s->max_exec = addr;
		}
	}
	if (print) {
		printk(KERN_INFO
			" 4k %lu large %lu gb %lu huge %lu x %lu[%lx-%lx] miss %lu\n",
			s->spg, s->lpg, s->gpg, s->hpg, s->exec,
			s->min_exec != ~0UL ? s->min_exec : 0,
			s->max_exec, missed);
	}

	expected = (s->hpg*HPS + s->gpg*GPS + s->lpg*LPS)/PAGE_SIZE +
		   s->spg + missed;
	if (expected != i - min_test_pfn) {
		printk(KERN_ERR "CPA max_test_pfn %lu but expected %lu\n",
			max_test_pfn, expected);
		return 1;
	}
	return 0;
}

static unsigned long addr[NTEST];
static unsigned int len[NTEST];

static struct page *pages[NPAGES];
static unsigned long addrs[NPAGES];

/* Change the global bit on random pages in the direct mapping */
static int pageattr_test(void)
{
	struct split_state sa, sb, sc;
	struct cpa_test_leaf leaf, leaf0;
	unsigned long *bm;
	int failed = 0;
	int i, k;
	int err;

	if (print)
		printk(KERN_INFO "CPA self-test:\n");

	bm = vzalloc((max_test_pfn + 7) / 8);
	if (!bm) {
		printk(KERN_ERR "CPA Cannot vmalloc bitmap\n");
		return -ENOMEM;
	}

	failed += print_split(&sa);

	for (i = 0; i < NTEST; i++) {
		unsigned long pfn = min_test_pfn +
			get_random_u32_below(max_test_pfn - min_test_pfn);

		addr[i] = (unsigned long)__va(pfn << PAGE_SHIFT);
		len[i] = get_random_u32_below(NPAGES);
		len[i] = min_t(unsigned long, len[i], max_test_pfn - pfn - 1);

		if (len[i] == 0)
			len[i] = 1;

		for (k = 0; k < len[i]; k++) {
			if (cpa_test_lookup(addr[i] + k*PAGE_SIZE, &leaf) ||
			    pgprot_val(pte_pgprot(leaf.pte)) == 0 ||
			    !pte_present(leaf.pte)) {
				addr[i] = 0;
				break;
			}
			if (k == 0) {
				leaf0 = leaf;
			} else {
				if (pgprot_val(pte_pgprot(leaf.pte)) !=
				    pgprot_val(pte_pgprot(leaf0.pte))) {
					len[i] = k;
					break;
				}
			}
			if (test_bit(pfn + k, bm)) {
				len[i] = k;
				break;
			}
			__set_bit(pfn + k, bm);
			addrs[k] = addr[i] + k*PAGE_SIZE;
			pages[k] = pfn_to_page(pfn + k);
		}
		if (!addr[i] || !k) {
			addr[i] = 0;
			continue;
		}

		switch (i % 3) {
		case 0:
			err = change_page_attr_set_clr(&addr[i], len[i],
						       ARCH_PAGE_CPA_TEST,
						       __pgprot(0), 0, NULL);
			break;

		case 1:
			err = change_page_attr_set_clr(addrs, len[i],
						       ARCH_PAGE_CPA_TEST,
						       __pgprot(0),
						       CPA_REQ_ARRAY, NULL);
			break;

		case 2:
			err = change_page_attr_set_clr(NULL, len[i],
						       ARCH_PAGE_CPA_TEST,
						       __pgprot(0),
						       CPA_REQ_PAGES_ARRAY, pages);
			break;
		}


		if (err < 0) {
			printk(KERN_ERR "CPA %d failed %d\n", i, err);
			failed++;
		}

		if (cpa_test_lookup(addr[i], &leaf) || !pte_testbit(leaf.pte)) {
			printk(KERN_ERR "CPA %lx: bad pte %Lx\n", addr[i],
				(u64)pte_val(leaf.pte));
			failed++;
		} else if (leaf.level != PGTABLE_LEVEL_PTE) {
			printk(KERN_ERR "CPA %lx: unexpected level %d\n",
				addr[i], leaf.level);
			failed++;
		}

	}
	vfree(bm);

	failed += print_split(&sb);

	for (i = 0; i < NTEST; i++) {
		if (!addr[i])
			continue;
		if (cpa_test_lookup(addr[i], &leaf)) {
			printk(KERN_ERR "CPA lookup of %lx failed\n", addr[i]);
			failed++;
			continue;
		}
		err = change_page_attr_set_clr(&addr[i], len[i], __pgprot(0),
					       ARCH_PAGE_CPA_TEST, 0, NULL);
		if (err < 0) {
			printk(KERN_ERR "CPA reverting failed: %d\n", err);
			failed++;
		}
		if (cpa_test_lookup(addr[i], &leaf) || pte_testbit(leaf.pte)) {
			printk(KERN_ERR "CPA %lx: bad pte after revert %Lx\n",
				addr[i], (u64)pte_val(leaf.pte));
			failed++;
		}

	}

	failed += print_split(&sc);

	if (failed) {
		WARN(1, KERN_ERR "NOT PASSED. Please report.\n");
		return -EINVAL;
	} else {
		if (print)
			printk(KERN_INFO "ok.\n");
	}

	return 0;
}

static int do_pageattr_test(void *__unused)
{
	while (!kthread_should_stop()) {
		schedule_timeout_interruptible(HZ*30);
		if (pageattr_test() < 0)
			break;
		if (print)
			print--;
	}
	return 0;
}

static int start_pageattr_test(void)
{
	struct task_struct *p;

	min_test_pfn = PFN_DOWN(__pa(PAGE_OFFSET));
	max_test_pfn = PFN_DOWN(__pa(high_memory - 1)) + 1;

	p = kthread_create(do_pageattr_test, NULL, "pageattr-test");
	if (!IS_ERR(p))
		wake_up_process(p);
	else
		WARN_ON(1);

	return 0;
}
device_initcall(start_pageattr_test);
