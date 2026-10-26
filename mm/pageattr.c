// SPDX-License-Identifier: GPL-2.0-only
/*
 * Changing permissions of the kernel page tables.
 *
 * A request is processed in two passes over its range. The prepare pass
 * splits the leaves that are not entirely covered by the request and checks
 * that every leaf can be changed and the apply pass changes them. Splitting
 * does not change permissions.
 *
 * After a request completes, either successfully or not, the tables that
 * map a range with uniform permissions are replaced with large leaves.
 * All errors are reported by the prepare pass, so a failed request does not
 * change any permission.
 */
#include <linux/kfence.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/pageattr.h>

/* returned by the prepare pass when the leaf must be looked up again */
#define CPA_RETRY	1

enum cpa_pass {
	CPA_PREPARE,
	CPA_APPLY,
};

static DEFINE_MUTEX(cpa_mutex);

static unsigned long cpa_level_size(enum pgtable_level level)
{
	switch (level) {
	case PGTABLE_LEVEL_PTE:
		return PAGE_SIZE;
	case PGTABLE_LEVEL_PMD:
		return PMD_SIZE;
	case PGTABLE_LEVEL_PUD:
		return PUD_SIZE;
	case PGTABLE_LEVEL_P4D:
		return P4D_SIZE;
	default:
		return PGDIR_SIZE;
	}
}

static void *cpa_entry_offset(void *entry, enum pgtable_level level, long n)
{
	switch (level) {
	case PGTABLE_LEVEL_PTE:
		return (pte_t *)entry + n;
	case PGTABLE_LEVEL_PMD:
		return (pmd_t *)entry + n;
	case PGTABLE_LEVEL_PUD:
		return (pud_t *)entry + n;
	default:
		return (p4d_t *)entry + n;
	}
}

static void cpa_decode_leaf(unsigned long addr, struct cpa_leaf *leaf)
{
	unsigned long size = cpa_level_size(leaf->level);
	unsigned long idx;

	leaf->nr = 1;
	arch_cpa_read_leaf(leaf);

	leaf->size = size * leaf->nr;
	leaf->start = ALIGN_DOWN(addr, leaf->size);
	idx = (ALIGN_DOWN(addr, size) - leaf->start) / size;
	leaf->entry = cpa_entry_offset(leaf->entry, leaf->level, -idx);
	leaf->pfn -= idx * (size >> PAGE_SHIFT);
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
	if (arch_cpa_p4d_leaf(p4dp_get(p4dp)))
		goto found;

	pudp = pud_offset(p4dp, addr);
	leaf->level = PGTABLE_LEVEL_PUD;
	leaf->entry = pudp;
	if (pud_none(pudp_get(pudp)))
		return -ENOENT;
	if (arch_cpa_pud_leaf(pudp_get(pudp)))
		goto found;

	pmdp = pmd_offset(pudp, addr);
	leaf->level = PGTABLE_LEVEL_PMD;
	leaf->entry = pmdp;
	if (pmd_none(pmdp_get(pmdp)))
		return -ENOENT;
	if (arch_cpa_pmd_leaf(pmdp_get(pmdp)))
		goto found;

	ptep = pte_offset_kernel(pmdp, addr);
	leaf->level = PGTABLE_LEVEL_PTE;
	leaf->entry = ptep;
	if (pte_none(ptep_get(ptep)))
		return -ENOENT;

found:
	cpa_decode_leaf(addr, leaf);
	return 0;
}

static int cpa_split_leaf(struct cpa_req *req, struct cpa_leaf *leaf,
			  unsigned long addr)
{
	enum pgtable_level level = leaf->level - 1;
	void *table;
	int err;

	if (leaf->nr > 1) {
		err = arch_cpa_split_group(req, leaf);
		return err ?: CPA_RETRY;
	}

	if (leaf->level == PGTABLE_LEVEL_PTE)
		return -EINVAL;

	table = arch_cpa_alloc_table(req, level, ALIGN_DOWN(addr, leaf->size));
	if (!table)
		return -ENOMEM;

	err = arch_cpa_split(req, leaf, table);
	if (err) {
		arch_cpa_free_table(req, level, table);
		return err;
	}

	return CPA_RETRY;
}

static int cpa_process_leaf(struct cpa_req *req, struct cpa_leaf *leaf,
			    unsigned long start, unsigned long end,
			    enum cpa_pass pass)
{
	unsigned long leaf_end = leaf->start + leaf->size;
	pgprot_t prot;
	bool uniform;

	uniform = arch_cpa_new_prot(req, leaf, start, end, &prot);
	if (uniform && pgprot_val(prot) == pgprot_val(leaf->prot))
		return 0;

	if (!uniform || start != leaf->start || end != leaf_end) {
		/* the prepare pass made sure that this cannot happen */
		if (WARN_ON_ONCE(pass == CPA_APPLY))
			return -EINVAL;
		return cpa_split_leaf(req, leaf, start);
	}

	if (pass == CPA_PREPARE)
		return 0;

	arch_cpa_write_leaf(req, leaf, prot);
	req->flush_start = min(req->flush_start, leaf->start);
	req->flush_end = max(req->flush_end, leaf_end);

	return 0;
}

static int cpa_process_range(struct cpa_req *req, enum cpa_pass pass)
{
	unsigned long end = req->addr + req->numpages * PAGE_SIZE;
	unsigned long addr = req->addr;
	struct cpa_leaf leaf;
	unsigned long next;
	int err;

	while (addr < end) {
		err = cpa_lookup(addr, &leaf);
		if (err) {
			next = ALIGN_DOWN(addr, cpa_level_size(leaf.level)) +
			       cpa_level_size(leaf.level);
			err = arch_cpa_hole(req, addr);
		} else {
			next = leaf.start + leaf.size;
			err = cpa_process_leaf(req, &leaf, addr,
					       min(next - 1, end - 1) + 1, pass);
			if (err == CPA_RETRY)
				continue;
		}
		if (err)
			return err;

		if (next - 1 >= end - 1)
			break;
		addr = next;
	}

	return 0;
}

/*
 * Return the entry at @level that maps @addr if it points to a table.
 */
static void *cpa_table_entry(unsigned long addr, enum pgtable_level level)
{
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp;
	pmd_t *pmdp;
	pud_t pud;
	pmd_t pmd;

	pgdp = pgd_offset_k(addr);
	if (pgd_none(pgdp_get(pgdp)))
		return NULL;

	p4dp = p4d_offset(pgdp, addr);
	if (p4d_none(p4dp_get(p4dp)) || arch_cpa_p4d_leaf(p4dp_get(p4dp)))
		return NULL;

	pudp = pud_offset(p4dp, addr);
	pud = pudp_get(pudp);
	if (pud_none(pud) || arch_cpa_pud_leaf(pud))
		return NULL;
	if (level == PGTABLE_LEVEL_PUD)
		return pudp;

	pmdp = pmd_offset(pudp, addr);
	pmd = pmdp_get(pmdp);
	if (pmd_none(pmd) || arch_cpa_pmd_leaf(pmd))
		return NULL;

	return pmdp;
}

static bool cpa_child_is_leaf(void *entry, enum pgtable_level level)
{
	pmd_t pmd;

	if (level == PGTABLE_LEVEL_PTE)
		return !pte_none(ptep_get((pte_t *)entry));

	pmd = pmdp_get((pmd_t *)entry);
	return !pmd_none(pmd) && arch_cpa_pmd_leaf(pmd);
}

/*
 * Check if all the entries of @table are leaves that map contiguous pfns
 * with the same protections, and if so describe the leaf that can replace
 * the table in @leaf.
 */
static bool cpa_table_is_uniform(void *table, struct cpa_leaf *leaf)
{
	enum pgtable_level level = leaf->level - 1;
	unsigned long child_pages = cpa_level_size(level) >> PAGE_SHIFT;
	unsigned long nr = leaf->size / cpa_level_size(level);
	struct cpa_leaf child = { .level = level };
	unsigned long i;

	for (i = 0; i < nr; i++) {
		child.entry = cpa_entry_offset(table, level, i);
		if (!cpa_child_is_leaf(child.entry, level))
			return false;

		child.nr = 1;
		arch_cpa_read_leaf(&child);

		if (!i) {
			if (!IS_ALIGNED(child.pfn, leaf->size >> PAGE_SHIFT))
				return false;
			leaf->pfn = child.pfn;
			leaf->prot = child.prot;
			continue;
		}

		if (child.pfn != leaf->pfn + i * child_pages ||
		    pgprot_val(child.prot) != pgprot_val(leaf->prot))
			return false;
	}

	return true;
}

/* KFENCE changes its pool without the generic code */
static bool cpa_overlaps_kfence(unsigned long start, unsigned long end)
{
#ifdef CONFIG_KFENCE
	unsigned long pool = (unsigned long)__kfence_pool;

	if (pool && start < pool + KFENCE_POOL_SIZE && pool < end)
		return true;
#endif
	return false;
}

/* modules and vmalloc may be above PAGE_OFFSET and pass virt_addr_valid() */
static bool cpa_in_direct_map(unsigned long addr)
{
	return !is_vmalloc_or_module_addr((void *)addr) &&
	       virt_addr_valid((void *)addr);
}

static bool cpa_may_collapse(struct cpa_req *req, unsigned long start,
			     unsigned long end, unsigned long req_start,
			     unsigned long req_end)
{
	if (cpa_overlaps_kfence(start, end))
		return false;

	if (req->flags & CPA_COLLAPSE)
		return true;

	if (start >= req_start && end <= req_end)
		return true;

	/* only the generic code changes the direct map */
	return cpa_in_direct_map(start) && cpa_in_direct_map(end - 1);
}

static void cpa_collapse_level(struct cpa_req *req, enum pgtable_level level,
			       unsigned long start, unsigned long end)
{
	unsigned long size = cpa_level_size(level);
	unsigned long addr;

	if (!arch_cpa_can_collapse(req, level))
		return;

	for (addr = ALIGN_DOWN(start, size); addr < end; addr += size) {
		struct cpa_leaf leaf = {
			.level = level,
			.start = addr,
			.size = size,
			.nr = 1,
		};
		void *table;

		if (!cpa_may_collapse(req, addr, addr + size, start, end))
			goto next;

		leaf.entry = cpa_table_entry(addr, level);
		if (!leaf.entry)
			goto next;

		if (level == PGTABLE_LEVEL_PMD)
			table = pte_offset_kernel(leaf.entry, addr);
		else
			table = pmd_offset(leaf.entry, addr);

		if (!cpa_table_is_uniform(table, &leaf))
			goto next;

		if (!arch_cpa_collapse(req, &leaf))
			goto next;

		/* tables allocated at boot are not page tables, leak them */
		if (PageTable(virt_to_page(table)))
			arch_cpa_free_table(req, level - 1, table);
next:
		/* the last block of the address space */
		if (addr + size < addr)
			break;
	}
}

static void cpa_collapse(struct cpa_req *req)
{
	unsigned long start = req->addr;
	unsigned long end = start + req->numpages * PAGE_SIZE;

	if (debug_pagealloc_enabled())
		return;

	cpa_collapse_level(req, PGTABLE_LEVEL_PMD, start, end);

	/* a PUD leaf replaces a table of PMDs */
	if (!mm_pmd_folded(&init_mm))
		cpa_collapse_level(req, PGTABLE_LEVEL_PUD, start, end);
}

/**
 * cpa_change - change permissions of a range of kernel mappings
 * @req: the request
 *
 * Context: process context, may sleep.
 * Return: 0 on success or a negative error code. On failure the permissions
 * of the range are not changed.
 */
int cpa_change(struct cpa_req *req)
{
	int err;

	if (!req->numpages)
		return 0;

	might_sleep();

	req->flush_start = ULONG_MAX;
	req->flush_end = 0;

	mutex_lock(&cpa_mutex);

	err = cpa_process_range(req, CPA_PREPARE);
	if (err)
		goto collapse;

	arch_cpa_enter(req);
	err = cpa_process_range(req, CPA_APPLY);
	arch_cpa_leave(req);

	if (!(req->flags & CPA_NOFLUSH) && req->flush_start < req->flush_end)
		arch_cpa_flush(req);

collapse:
	cpa_collapse(req);
	mutex_unlock(&cpa_mutex);
	return err;
}
