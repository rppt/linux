// SPDX-License-Identifier: GPL-2.0-only
/*
 * Changing permissions of the kernel page tables.
 *
 * A request is processed in two passes over its range. The prepare pass
 * checks that every leaf can be changed and the apply pass changes them.
 * All errors are reported by the prepare pass, so a failed request does not
 * change any permission.
 */
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/pageattr.h>

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
		WARN_ON_ONCE(pass == CPA_APPLY);
		return -EINVAL;
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
		}
		if (err)
			return err;

		if (next - 1 >= end - 1)
			break;
		addr = next;
	}

	return 0;
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
		goto unlock;

	arch_cpa_enter(req);
	err = cpa_process_range(req, CPA_APPLY);
	arch_cpa_leave(req);

	if (!(req->flags & CPA_NOFLUSH) && req->flush_start < req->flush_end)
		arch_cpa_flush(req);

unlock:
	mutex_unlock(&cpa_mutex);
	return err;
}
