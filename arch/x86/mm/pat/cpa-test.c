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
#include <linux/vmalloc.h>

/*
 * Only print the results of the first pass:
 */
static __read_mostly int print = 1;
static unsigned long min_test_pfn, max_test_pfn;

enum {
	NTEST			= 2 * 100,
	NPAGES			= 100,
	LPS			= PMD_SIZE,
	GPS			= PUD_SIZE
};

static int pte_testbit(pte_t pte)
{
	return pte_val(pte) & pgprot_val(PAGE_CPA_TEST);
}

static pte_t *cpa_test_lookup(unsigned long address, unsigned int *level)
{
	struct cpa_data cpa = {};
	struct cpa_leaf leaf;
	pte_t *pte;

	pte = arch_cpa_lookup_leaf(&cpa, address, &leaf);
	if (pte)
		*level = leaf.level;

	return pte;
}

struct split_state {
	long lpg, gpg, spg;
};

static int print_split(struct split_state *s)
{
	long i, expected, missed = 0;

	s->lpg = s->gpg = s->spg = 0;
	for (i = min_test_pfn; i < max_test_pfn; ) {
		unsigned long addr = (unsigned long)__va(i << PAGE_SHIFT);
		unsigned int level;
		pte_t *pte;

		pte = cpa_test_lookup(addr, &level);
		if (!pte) {
			missed++;
			i++;
			continue;
		}

		if (level == PGTABLE_LEVEL_PUD && sizeof(long) == 8) {
			s->gpg++;
			i += GPS/PAGE_SIZE;
		} else if (level == PGTABLE_LEVEL_PMD) {
			s->lpg++;
			i += LPS/PAGE_SIZE;
		} else {
			s->spg++;
			i++;
		}
	}
	if (print) {
		printk(KERN_INFO
			" 4k %lu large %lu gb %lu miss %lu\n",
			s->spg, s->lpg, s->gpg, missed);
	}

	expected = (s->gpg*GPS + s->lpg*LPS)/PAGE_SIZE + s->spg + missed;
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

/* Change the global bit on random pages in the direct mapping */
static int pageattr_test(void)
{
	struct split_state sa, sb, sc;
	unsigned long *bm;
	pte_t *pte, pte0, pteval;
	int failed = 0;
	unsigned int level;
	int i, k;
	int err;

	if (print)
		printk(KERN_INFO "CPA self-test:\n");

	bm = vzalloc((max_test_pfn - min_test_pfn + 7) / 8);
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

		pte = NULL;
		pte0 = pfn_pte(0, __pgprot(0)); /* shut gcc up */

		for (k = 0; k < len[i]; k++) {
			pte = cpa_test_lookup(addr[i] + k*PAGE_SIZE, &level);
			if (!pte) {
				addr[i] = 0;
				break;
			}
			pteval = ptep_get(pte);
			if (pgprot_val(pte_pgprot(pteval)) == 0 ||
			    !pte_present(pteval)) {
				addr[i] = 0;
				break;
			}
			if (k == 0) {
				pte0 = pteval;
			} else {
				if (pgprot_val(pte_pgprot(pteval)) !=
					pgprot_val(pte_pgprot(pte0))) {
					len[i] = k;
					break;
				}
			}
			if (test_bit(pfn + k - min_test_pfn, bm)) {
				len[i] = k;
				break;
			}
			__set_bit(pfn + k - min_test_pfn, bm);
			pages[k] = pfn_to_page(pfn + k);
		}
		if (!addr[i] || !pte || !k) {
			addr[i] = 0;
			continue;
		}

		if (i % 2)
			err = cpa_set_clr(0, len[i], PAGE_CPA_TEST,
					  __pgprot(0), CPA_REQ_PAGES_ARRAY,
					  pages);
		else
			err = change_page_attr_set(addr[i], len[i], PAGE_CPA_TEST);


		if (err < 0) {
			printk(KERN_ERR "CPA %d failed %d\n", i, err);
			failed++;
		}

		pte = cpa_test_lookup(addr[i], &level);
		if (!pte || !pte_testbit(ptep_get(pte))) {
			printk(KERN_ERR "CPA %lx: bad pte %Lx\n", addr[i],
				pte ? (u64)pte_val(ptep_get(pte)) : 0ULL);
			failed++;
		}
		if (level != PGTABLE_LEVEL_PTE) {
			printk(KERN_ERR "CPA %lx: unexpected level %d\n",
				addr[i], level);
			failed++;
		}

	}
	vfree(bm);

	failed += print_split(&sb);

	for (i = 0; i < NTEST; i++) {
		if (!addr[i])
			continue;
		pte = cpa_test_lookup(addr[i], &level);
		if (!pte) {
			printk(KERN_ERR "CPA lookup of %lx failed\n", addr[i]);
			failed++;
			continue;
		}
		err = change_page_attr_clear(addr[i], len[i], PAGE_CPA_TEST);
		if (err < 0) {
			printk(KERN_ERR "CPA reverting failed: %d\n", err);
			failed++;
		}
		pte = cpa_test_lookup(addr[i], &level);
		if (!pte || pte_testbit(ptep_get(pte))) {
			printk(KERN_ERR "CPA %lx: bad pte after revert %Lx\n",
				addr[i], pte ? (u64)pte_val(ptep_get(pte)) : 0ULL);
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

	min_test_pfn = min_low_pfn;
	max_test_pfn = PFN_DOWN(__pa(high_memory - 1)) + 1;

	p = kthread_create(do_pageattr_test, NULL, "pageattr-test");
	if (!IS_ERR(p))
		wake_up_process(p);
	else
		WARN_ON(1);

	return 0;
}
device_initcall(start_pageattr_test);
