// SPDX-License-Identifier: GPL-2.0-only
/*
 * Changing permissions of the kernel page tables.
 *
 * A request is processed in two passes over its range. cpa_prepare() splits
 * the leaves that are not entirely covered by the request and checks that
 * every leaf can be changed, cpa_update() changes them. Splitting does not
 * change permissions, so a failed request does not change any permission.
 *
 * The TLB maintenance after a request is up to the architecture.
 */
#include <linux/kasan.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/pageattr.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>

static DEFINE_MUTEX(cpa_mutex);

static void cpa_lock(struct cpa_req *req)
{
	might_sleep();
	mutex_lock(&cpa_mutex);
}

static void cpa_unlock(struct cpa_req *req)
{
	mutex_unlock(&cpa_mutex);
}

static unsigned long cpa_level_size(enum pgtable_level level)
{
	/* not static, P4D_SIZE and PGDIR_SIZE may be variables */
	const unsigned long size[] = {
		[PGTABLE_LEVEL_PTE] = PAGE_SIZE,
		[PGTABLE_LEVEL_PMD] = PMD_SIZE,
		[PGTABLE_LEVEL_PUD] = PUD_SIZE,
		[PGTABLE_LEVEL_P4D] = P4D_SIZE,
		[PGTABLE_LEVEL_PGD] = PGDIR_SIZE,
	};

	return size[level];
}

static void *cpa_entry_offset(void *entry, enum pgtable_level level, long n)
{
	static const size_t size[] = {
		[PGTABLE_LEVEL_PTE] = sizeof(pte_t),
		[PGTABLE_LEVEL_PMD] = sizeof(pmd_t),
		[PGTABLE_LEVEL_PUD] = sizeof(pud_t),
		[PGTABLE_LEVEL_P4D] = sizeof(p4d_t),
		[PGTABLE_LEVEL_PGD] = sizeof(pgd_t),
	};

	return entry + n * (long)size[level];
}

static bool cpa_read_leaf(unsigned long addr, struct cpa_leaf *leaf)
{
	unsigned long size = cpa_level_size(leaf->level);
	unsigned long idx;

	leaf->nr = 1;
	if (!arch_cpa_read_leaf(leaf))
		return false;

	leaf->size = size * leaf->nr;
	leaf->start = ALIGN_DOWN(addr, leaf->size);
	idx = (ALIGN_DOWN(addr, size) - leaf->start) / size;
	leaf->entry = cpa_entry_offset(leaf->entry, leaf->level, -idx);
	leaf->pfn -= idx * (size >> PAGE_SHIFT);

	return true;
}

/*
 * Find the leaf that maps @addr. If @addr is not mapped, return -ENOENT with
 * @leaf->level set to the level of the empty entry.
 */
static int cpa_lookup(unsigned long addr, struct cpa_leaf *leaf)
{
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;

	pgdp = pgd_offset_k(addr);
	leaf->level = PGTABLE_LEVEL_PGD;
	if (pgd_none(pgdp_get(pgdp)))
		return -ENOENT;

	p4dp = p4d_offset(pgdp, addr);
	leaf->level = PGTABLE_LEVEL_P4D;
	leaf->entry = p4dp;
	if (p4d_none(p4dp_get(p4dp)))
		return -ENOENT;
	if (cpa_read_leaf(addr, leaf))
		return 0;

	pudp = pud_offset(p4dp, addr);
	leaf->level = PGTABLE_LEVEL_PUD;
	leaf->entry = pudp;
	if (pud_none(pudp_get(pudp)))
		return -ENOENT;
	if (cpa_read_leaf(addr, leaf))
		return 0;

	pmdp = pmd_offset(pudp, addr);
	leaf->level = PGTABLE_LEVEL_PMD;
	leaf->entry = pmdp;
	if (pmd_none(pmdp_get(pmdp)))
		return -ENOENT;
	if (cpa_read_leaf(addr, leaf))
		return 0;

	ptep = pte_offset_kernel(pmdp, addr);
	leaf->level = PGTABLE_LEVEL_PTE;
	leaf->entry = ptep;
	if (pte_none(ptep_get(ptep)))
		return -ENOENT;
	if (cpa_read_leaf(addr, leaf))
		return 0;

	return -EINVAL;
}

/* the end of a leaf or a hole may be past @range or wrap around to 0 */
static unsigned long cpa_clamp(struct cpa_range *range, unsigned long addr)
{
	if (addr - range->start > range->end - range->start)
		return range->end;
	return addr;
}

/*
 * Find the leaf that maps @addr and set @next to the end of the part of
 * @range it maps. Holes fail the request.
 */
static int cpa_find_leaf(struct cpa_range *range, unsigned long addr,
			 struct cpa_leaf *leaf, unsigned long *next)
{
	int err;

	err = cpa_lookup(addr, leaf);
	if (err == -ENOENT)
		return -EFAULT;
	if (err)
		return err;

	*next = cpa_clamp(range, leaf->start + leaf->size);
	return 0;
}

/*
 * Check if the part [@start, @end) of @leaf must be split before it can be
 * changed. If not, set @prot to the new protections of @leaf.
 */
static bool cpa_must_split(struct cpa_req *req, struct cpa_range *range,
			   struct cpa_leaf *leaf, unsigned long start,
			   unsigned long end, pgprot_t *prot)
{
	*prot = leaf->prot;

	if (!arch_cpa_new_prot(req, range, leaf, start, end, prot))
		return true;

	if (pgprot_val(*prot) == pgprot_val(leaf->prot))
		return false;

	return start != leaf->start || end != leaf->start + leaf->size;
}

static int cpa_split(struct cpa_req *req, struct cpa_leaf *leaf)
{
	int err;

	if (WARN_ON_ONCE(leaf->size == PAGE_SIZE))
		return -EINVAL;

	err = arch_cpa_split(req, leaf);
	if (err)
		return err;

	req->changed |= CPA_CHANGED_SPLIT;
	return 0;
}

static int cpa_prepare_range(struct cpa_req *req, struct cpa_range *range)
{
	unsigned long addr, next;
	struct cpa_leaf leaf;
	pgprot_t prot;
	int err;

	for (addr = range->start; addr != range->end; addr = next) {
		err = cpa_find_leaf(range, addr, &leaf, &next);
		if (err)
			return err;

		if (!cpa_must_split(req, range, &leaf, addr, next, &prot))
			continue;

		err = cpa_split(req, &leaf);
		if (err)
			return err;
		/* look up the new leaf */
		next = addr;
	}

	return 0;
}

static void cpa_update_leaf(struct cpa_req *req, struct cpa_range *range,
			    struct cpa_leaf *leaf, unsigned long start,
			    unsigned long end)
{
	pgprot_t prot;

	/* cpa_prepare() split everything that had to be split */
	if (WARN_ON_ONCE(cpa_must_split(req, range, leaf, start, end, &prot)))
		return;

	if (pgprot_val(prot) == pgprot_val(leaf->prot))
		return;

	arch_cpa_write_leaf(req, leaf, prot);
	req->changed |= CPA_CHANGED_PROT;
}

static void cpa_update_range(struct cpa_req *req, struct cpa_range *range)
{
	unsigned long addr, next;
	struct cpa_leaf leaf;
	int err;

	for (addr = range->start; addr != range->end; addr = next) {
		err = cpa_find_leaf(range, addr, &leaf, &next);
		if (WARN_ON_ONCE(err))
			return;

		cpa_update_leaf(req, range, &leaf, addr, next);
	}
}

static struct cpa_range cpa_req_range(struct cpa_req *req)
{
	return (struct cpa_range) {
		.start = req->addr,
		.end = req->addr + req->numpages * PAGE_SIZE,
		.set = req->set,
		.clr = req->clr,
	};
}

static int cpa_prepare(struct cpa_req *req)
{
	struct cpa_range range = cpa_req_range(req);

	return cpa_prepare_range(req, &range);
}

static void cpa_update(struct cpa_req *req)
{
	struct cpa_range range = cpa_req_range(req);

	lazy_mmu_mode_enable();
	cpa_update_range(req, &range);
	lazy_mmu_mode_disable();
}

static bool cpa_req_valid(struct cpa_req *req)
{
	unsigned long end;

	if (req->numpages > ULONG_MAX >> PAGE_SHIFT)
		return false;

	end = req->addr + req->numpages * PAGE_SIZE;
	return end > req->addr;
}

/**
 * cpa_change - change permissions of a range of kernel mappings
 * @req: the request
 *
 * Context: process context, may sleep.
 * Return: 0 on success or a negative error code. On failure the permissions
 * are not changed, but leaves may have been split.
 */
int cpa_change(struct cpa_req *req)
{
	int err;

	req->addr = (unsigned long)kasan_reset_tag((void *)req->addr);
	req->changed = 0;

	if (!req->numpages)
		return 0;

	if (!cpa_req_valid(req))
		return -EINVAL;

	err = arch_cpa_check(req);
	if (err)
		return err;

	cpa_lock(req);

	err = cpa_prepare(req);
	if (!err)
		cpa_update(req);

	if (req->changed)
		arch_cpa_flush(req);

	cpa_unlock(req);

	return err;
}

/**
 * cpa_alloc_table - allocate a page table to split a leaf
 * @req: the request
 * @level: level of the entries in the new table
 * @addr: virtual address mapped by the new table
 *
 * Return: the new table or NULL.
 */
void *cpa_alloc_table(struct cpa_req *req, enum pgtable_level level,
		      unsigned long addr)
{
	switch (level) {
	case PGTABLE_LEVEL_PTE:
		return pte_alloc_one_kernel(&init_mm);
	case PGTABLE_LEVEL_PMD:
		return pmd_alloc_one(&init_mm, addr);
	case PGTABLE_LEVEL_PUD:
		return pud_alloc_one(&init_mm, addr);
	default:
		return NULL;
	}
}

/**
 * cpa_free_table - free a page table allocated with cpa_alloc_table()
 * @level: level of the entries in the table
 * @table: the table
 */
void cpa_free_table(enum pgtable_level level, void *table)
{
	switch (level) {
	case PGTABLE_LEVEL_PTE:
		pte_free_kernel(&init_mm, table);
		break;
	case PGTABLE_LEVEL_PMD:
		pmd_free(&init_mm, table);
		break;
	case PGTABLE_LEVEL_PUD:
		pud_free(&init_mm, table);
		break;
	default:
		break;
	}
}

/**
 * cpa_flush_ranges - flush the TLB for the leaves changed by a request
 * @req: the request
 *
 * Helper for arch_cpa_flush() that flushes the range of @req with
 * flush_tlb_kernel_range().
 */
void cpa_flush_ranges(struct cpa_req *req)
{
	if (req->changed & CPA_CHANGED_PROT)
		flush_tlb_kernel_range(req->addr,
				       req->addr + req->numpages * PAGE_SIZE);
}
