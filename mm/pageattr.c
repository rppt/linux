// SPDX-License-Identifier: GPL-2.0-only
/*
 * Changing permissions of the kernel page tables.
 *
 * A request is processed in two passes over its range. cpa_prepare() splits
 * the leaves that are not entirely covered by the request and checks that
 * every leaf can be changed, cpa_update() changes them. Splitting does not
 * change permissions, so a failed request does not change any permission.
 *
 * Every part of the request is processed together with its alias, the
 * direct map address of the same pages.
 *
 * The TLB maintenance after a request is up to the architecture.
 */
#include <linux/kasan.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/pageattr.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/set_memory.h>
#include <linux/vmalloc.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>

#include "internal.h"

static DEFINE_MUTEX(cpa_mutex);

static void cpa_lock(struct cpa_req *req)
{
	if (req->flags & CPA_ATOMIC)
		return;

	might_sleep();
	mutex_lock(&cpa_mutex);
}

static void cpa_unlock(struct cpa_req *req)
{
	if (req->flags & CPA_ATOMIC)
		return;

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
 * @range it maps. Holes in the range fail the request, holes in its aliases
 * are skipped.
 */
static int cpa_find_leaf(struct cpa_range *range, unsigned long addr,
			 struct cpa_leaf *leaf, unsigned long *next)
{
	unsigned long size;
	int err;

	err = cpa_lookup(addr, leaf);
	if (!err) {
		*next = cpa_clamp(range, leaf->start + leaf->size);
		return 0;
	}
	if (err != -ENOENT)
		return err;

	size = cpa_level_size(leaf->level);
	*next = cpa_clamp(range, ALIGN_DOWN(addr, size) + size);

	return range->alias ? -ENOENT : -EFAULT;
}

/*
 * Modules and vmalloc may be above PAGE_OFFSET and pass virt_addr_valid(),
 * and so may the kernel image mapping.
 */
static bool cpa_in_direct_map(unsigned long addr)
{
	if (is_vmalloc_or_module_addr((void *)addr))
		return false;
	if (!virt_addr_valid((void *)addr))
		return false;

	return (unsigned long)__va(__pa(addr)) == addr;
}

/*
 * Get the direct map alias of the part [@start, @end) of @leaf, if the leaf
 * is not in the direct map itself.
 */
static bool cpa_get_alias(struct cpa_req *req, struct cpa_range *range,
			  struct cpa_leaf *leaf, unsigned long start,
			  unsigned long end, struct cpa_range *alias)
{
	unsigned long pfn = leaf->pfn + ((start - leaf->start) >> PAGE_SHIFT);
	unsigned long last = pfn + ((end - start) >> PAGE_SHIFT) - 1;

	if (range->alias || (req->flags & CPA_NO_ALIAS))
		return false;
	if (!pgprot_val(req->alias_set) && !pgprot_val(req->alias_clr))
		return false;
	if (cpa_in_direct_map(start))
		return false;
	if (!pfn_valid(pfn) || !pfn_valid(last) ||
	    PageHighMem(pfn_to_page(pfn)) || PageHighMem(pfn_to_page(last)))
		return false;

	*alias = (struct cpa_range) {
		.start = (unsigned long)__va(PFN_PHYS(pfn)),
		.end = (unsigned long)__va(PFN_PHYS(last)) + PAGE_SIZE,
		.set = req->alias_set,
		.clr = req->alias_clr,
		.alias = true,
	};

	return true;
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

	if (req->flags & CPA_SPLIT)
		return leaf->size > PAGE_SIZE;

	if (!arch_cpa_new_prot(req, range, leaf, start, end, prot))
		return true;

	if (pgprot_val(*prot) == pgprot_val(leaf->prot))
		return false;

	return start != leaf->start || end != leaf->start + leaf->size;
}

#ifdef CONFIG_ARCH_HAS_DIRECT_MAP_COUNT
static atomic_long_t direct_map_entries[PGTABLE_LEVEL_PGD + 1];

/**
 * direct_map_count - account entries of the direct map
 * @level: level of the entries
 * @nr: number of mapped entries, negative for unmapped entries
 *
 * The architecture accounts the entries it maps and unmaps, the core
 * accounts splits.
 */
void direct_map_count(enum pgtable_level level, long nr)
{
	atomic_long_add(nr, &direct_map_entries[level]);
}

/* a split of a contiguous group does not change the number of entries */
static void direct_map_count_split(struct cpa_leaf *leaf)
{
	enum pgtable_level level = leaf->level;

	if (leaf->nr > 1 || !cpa_in_direct_map(leaf->start))
		return;

	direct_map_count(level, -1);
	direct_map_count(level - 1, leaf->size / cpa_level_size(level - 1));
}

#ifdef CONFIG_PROC_FS
static const struct {
	unsigned int shift;
	char unit;
} direct_map_units[] = {
	{ 30, 'G' },
	{ 20, 'M' },
	{ 10, 'k' },
};

static void direct_map_show_line(struct seq_file *m, unsigned long size,
				 unsigned long kb)
{
	char name[32];
	int i;

	for (i = 0; i < ARRAY_SIZE(direct_map_units) - 1; i++)
		if (IS_ALIGNED(size, 1UL << direct_map_units[i].shift))
			break;

	snprintf(name, sizeof(name), "DirectMap%lu%c:",
		 size >> direct_map_units[i].shift, direct_map_units[i].unit);
	seq_printf(m, "%-16s%8lu kB\n", name, kb);
}

static void direct_map_show(struct seq_file *m, enum pgtable_level level)
{
	unsigned long size = cpa_level_size(level);
	unsigned long nr = atomic_long_read(&direct_map_entries[level]);
	unsigned long cont_size;
	unsigned long cont;

	/* the counters are updated without synchronization with readers */
	cont = min(arch_direct_map_cont(level, &cont_size), nr);

	direct_map_show_line(m, size, (nr - cont) * (size >> 10));
	if (cont_size)
		direct_map_show_line(m, cont_size, cont * (size >> 10));
}

void arch_report_meminfo(struct seq_file *m)
{
	unsigned long levels = arch_direct_map_levels();
	unsigned int level;

	for_each_set_bit(level, &levels, PGTABLE_LEVEL_PGD + 1)
		direct_map_show(m, level);
}
#endif /* CONFIG_PROC_FS */
#else
static inline void direct_map_count_split(struct cpa_leaf *leaf) { }
#endif /* CONFIG_ARCH_HAS_DIRECT_MAP_COUNT */

static bool cpa_split_should_fail(struct cpa_req *req)
{
#ifdef CONFIG_PAGEATTR_KUNIT_TEST
	return req->fail_split && !--req->fail_split;
#else
	return false;
#endif
}

static int cpa_split(struct cpa_req *req, struct cpa_leaf *leaf)
{
	int err;

	if (WARN_ON_ONCE(leaf->size == PAGE_SIZE))
		return -EINVAL;

	if (cpa_split_should_fail(req))
		return -ENOMEM;

	err = arch_cpa_split(req, leaf);
	if (err)
		return err;

	direct_map_count_split(leaf);
	req->changed |= CPA_CHANGED_SPLIT;
	return 0;
}

static int cpa_prepare_range(struct cpa_req *req, struct cpa_range *range)
{
	unsigned long addr, next;
	struct cpa_range alias;
	struct cpa_leaf leaf;
	pgprot_t prot;
	int err;

	for (addr = range->start; addr != range->end; addr = next) {
		err = cpa_find_leaf(range, addr, &leaf, &next);
		if (err == -ENOENT)
			continue;
		if (err)
			return err;

		if (cpa_must_split(req, range, &leaf, addr, next, &prot)) {
			err = cpa_split(req, &leaf);
			if (err)
				return err;
			/* look up the new leaf */
			next = addr;
			continue;
		}

		if (!cpa_get_alias(req, range, &leaf, addr, next, &alias))
			continue;

		err = cpa_prepare_range(req, &alias);
		if (err)
			return err;
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
	req->changed |= range->alias ? CPA_CHANGED_ALIAS : CPA_CHANGED_PROT;
}

static void cpa_update_range(struct cpa_req *req, struct cpa_range *range)
{
	unsigned long addr, next;
	struct cpa_range alias;
	struct cpa_leaf leaf;
	int err;

	for (addr = range->start; addr != range->end; addr = next) {
		err = cpa_find_leaf(range, addr, &leaf, &next);
		if (err == -ENOENT)
			continue;
		if (WARN_ON_ONCE(err))
			return;

		cpa_update_leaf(req, range, &leaf, addr, next);

		if (cpa_get_alias(req, range, &leaf, addr, next, &alias))
			cpa_update_range(req, &alias);
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

static bool cpa_req_has_alias(struct cpa_req *req)
{
	if (req->flags & CPA_NO_ALIAS)
		return false;

	return pgprot_val(req->alias_set) || pgprot_val(req->alias_clr);
}

/**
 * cpa_change - change permissions of a range of kernel mappings
 * @req: the request
 *
 * Context: process context, may sleep, unless @req has CPA_ATOMIC.
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

	/*
	 * Lazily unmapped vmap aliases must not keep the old permissions,
	 * CPA_NOFLUSH callers take care of them.
	 */
	if (cpa_req_has_alias(req) &&
	    !(req->flags & (CPA_NOFLUSH | CPA_ATOMIC)))
		vm_unmap_aliases();

	cpa_lock(req);

	err = cpa_prepare(req);
	if (!err && !(req->flags & CPA_SPLIT))
		cpa_update(req);

	if (req->changed)
		arch_cpa_flush(req);

	cpa_unlock(req);

	return err;
}

/**
 * cpa_req_add_op - add a set_memory() operation to a request
 * @req: the request
 * @op: the operation
 */
void cpa_req_add_op(struct cpa_req *req, enum cpa_prot op)
{
	const struct cpa_prot_op *p = &arch_cpa_prot_ops[op];

	req->set = __pgprot(pgprot_val(req->set) | pgprot_val(p->set));
	req->clr = __pgprot(pgprot_val(req->clr) | pgprot_val(p->clr));
	if (!p->alias)
		return;

	req->alias_set = __pgprot(pgprot_val(req->alias_set) |
				  pgprot_val(p->set));
	req->alias_clr = __pgprot(pgprot_val(req->alias_clr) |
				  pgprot_val(p->clr));
}

/**
 * cpa_alloc_table - allocate a page table to split a leaf
 * @req: the request
 * @level: level of the entries in the new table
 * @addr: virtual address mapped by the new table
 *
 * Return: the new table or NULL. Always NULL for CPA_ATOMIC requests.
 */
void *cpa_alloc_table(struct cpa_req *req, enum pgtable_level level,
		      unsigned long addr)
{
	if (req->flags & CPA_ATOMIC)
		return NULL;

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
 * Helper for arch_cpa_flush() that flushes the range of @req and its
 * aliases with flush_tlb_kernel_range().
 */
void cpa_flush_ranges(struct cpa_req *req)
{
	struct cpa_range range = cpa_req_range(req);
	unsigned long addr, next, start = 0, end = 0;
	struct cpa_range alias;
	struct cpa_leaf leaf;

	if (req->changed & CPA_CHANGED_PROT)
		flush_tlb_kernel_range(range.start, range.end);

	if (!(req->changed & CPA_CHANGED_ALIAS))
		return;

	for (addr = range.start; addr != range.end; addr = next) {
		if (cpa_find_leaf(&range, addr, &leaf, &next))
			continue;
		if (!cpa_get_alias(req, &range, &leaf, addr, next, &alias))
			continue;

		if (alias.start == end) {
			end = alias.end;
			continue;
		}

		if (start != end)
			flush_tlb_kernel_range(start, end);
		start = alias.start;
		end = alias.end;
	}

	if (start != end)
		flush_tlb_kernel_range(start, end);
}

static int cpa_set_memory(struct cpa_req *req, int numpages)
{
	if (numpages <= 0)
		return 0;

	if (WARN_ON_ONCE(!PAGE_ALIGNED(req->addr)))
		return -EINVAL;

	req->numpages = numpages;
	return cpa_change(req);
}

static int cpa_set_memory_op(unsigned long addr, int numpages,
			     enum cpa_prot op)
{
	struct cpa_req req = { .addr = addr };

	cpa_req_add_op(&req, op);
	return cpa_set_memory(&req, numpages);
}

int set_memory_ro(unsigned long addr, int numpages)
{
	return cpa_set_memory_op(addr, numpages, CPA_PROT_RO);
}

int set_memory_rw(unsigned long addr, int numpages)
{
	return cpa_set_memory_op(addr, numpages, CPA_PROT_RW);
}

int set_memory_x(unsigned long addr, int numpages)
{
	return cpa_set_memory_op(addr, numpages, CPA_PROT_X);
}

int set_memory_nx(unsigned long addr, int numpages)
{
	return cpa_set_memory_op(addr, numpages, CPA_PROT_NX);
}

int set_memory_np(unsigned long addr, int numpages)
{
	return cpa_set_memory_op(addr, numpages, CPA_PROT_NP);
}

int set_memory_p(unsigned long addr, int numpages)
{
	return cpa_set_memory_op(addr, numpages, CPA_PROT_P);
}

int set_memory_rox(unsigned long addr, int numpages)
{
	struct cpa_req req = { .addr = addr };

	cpa_req_add_op(&req, CPA_PROT_RO);
	cpa_req_add_op(&req, CPA_PROT_X);
	return cpa_set_memory(&req, numpages);
}

#ifdef CONFIG_ARCH_HAS_SET_DIRECT_MAP
static int cpa_set_direct_map(struct page *page, unsigned int nr,
			      enum cpa_prot op)
{
	struct cpa_req req = {
		.addr = (unsigned long)page_address(page),
		.numpages = nr,
		.flags = CPA_NOFLUSH | CPA_NO_ALIAS,
	};

	if (!can_set_direct_map())
		return 0;

	cpa_req_add_op(&req, op);
	return cpa_change(&req);
}

int set_direct_map_invalid_noflush(struct page *page, unsigned int nr)
{
	return cpa_set_direct_map(page, nr, CPA_PROT_INVALID);
}

int set_direct_map_default_noflush(struct page *page, unsigned int nr)
{
	return cpa_set_direct_map(page, nr, CPA_PROT_DEFAULT);
}

/**
 * kernel_page_present - check if a page is present in the direct map
 * @page: the page
 *
 * The direct map tables are never freed, so the lookup does not need
 * cpa_mutex.
 *
 * Return: false if the direct map entry of @page is not present.
 */
bool kernel_page_present(struct page *page)
{
	const struct cpa_prot_op *p = &arch_cpa_prot_ops[CPA_PROT_P];
	unsigned long addr = (unsigned long)page_address(page);
	struct cpa_leaf leaf;

	if (cpa_lookup(addr, &leaf))
		return false;

	return ((pgprot_val(leaf.prot) & ~pgprot_val(p->clr)) |
		pgprot_val(p->set)) == pgprot_val(leaf.prot);
}
#endif /* CONFIG_ARCH_HAS_SET_DIRECT_MAP */

#if defined(CONFIG_PAGEATTR_KUNIT_TEST) || defined(CONFIG_DEBUG_PAGEATTR)
int cpa_lookup_locked(unsigned long addr, struct cpa_leaf *leaf)
{
	guard(mutex)(&cpa_mutex);
	return cpa_lookup(addr, leaf);
}
#endif
