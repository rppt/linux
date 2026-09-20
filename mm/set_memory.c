// SPDX-License-Identifier: GPL-2.0-only

#include <linux/cleanup.h>
#include <linux/highmem.h>
#include <linux/mmap_lock.h>
#include <linux/vmalloc.h>
#include <linux/pgtable.h>

#include <linux/set_memory.h>
#include <linux/pageattr.h>
#include <asm/pgalloc.h>

/*
 * Serialize cpa() so that we don't allow any other cpu, with stale large tlb
 * entries, to change the page attribute in parallel to some other cpu
 * splitting a large page entry along with changing the attribute.
 */
DEFINE_SPINLOCK(cpa_lock);

int __weak arch_cpa_prepare(struct cpa_data *cpa)
{
	return 0;
}

void __weak arch_cpa_finish_direct_map(struct cpa_data *cpa)
{
}

int __weak arch_cpa_process_alias(struct cpa_data *cpa)
{
	return 0;
}

int __weak arch_split_large_page(struct cpa_data *cpa,
				 struct cpa_split_data *sd)
{
	WARN_ON_ONCE(1);

	return -EINVAL;
}

unsigned long cpa_addr(struct cpa_data *cpa, unsigned long idx)
{
	if (cpa->req & CPA_REQ_PAGES_ARRAY) {
		struct page *page = cpa->pages[idx];

		if (unlikely(PageHighMem(page)))
			return 0;

		return (unsigned long)page_address(page);
	}

	if (cpa->req & CPA_REQ_ARRAY)
		return cpa->vaddr[idx];

	return *cpa->vaddr + idx * PAGE_SIZE;
}

static pte_t *lookup_address_cpa(struct cpa_data *cpa, unsigned long address,
				 enum pgtable_level *level, bool *nx, bool *rw)
{
	unsigned int lookup_level;
	pgd_t *pgd;
	pte_t *pte;

	if (cpa->pgd)
		pgd = cpa->pgd + pgd_index(address);
	else
		pgd = pgd_offset_k(address);

	pte = lookup_address_in_pgd_attr(pgd, address, &lookup_level, nx, rw);
	*level = lookup_level;

	return pte;
}

/**
 * cpa_revalidate_mapping - Look up and revalidate the expected mapping
 * @cpa: CPA operation selecting the page tables to walk
 * @sd: Split state containing the address and expected page table entry
 *
 * The caller must hold cpa_lock and any architecture-specific page table
 * lock through this call and the subsequent page table update.
 *
 * Refresh the mapping level and effective permissions without changing
 * the operation's page count.
 *
 * Return: 0 when the entry matches, or 1 when
 * the mapping changed and the caller must retry without using the old entry.
 */
int cpa_revalidate_mapping(struct cpa_data *cpa, struct cpa_split_data *sd)
{
	pte_t *tmp;

	/*
	 * Check for races, another CPU might have split this page
	 * up already:
	 */
	tmp = lookup_address_cpa(cpa, sd->address, &sd->level,
				 &sd->nx, &sd->rw);
	return tmp != sd->kpte;
}

/**
 * cpa_prepare_split - Prepare a large mapping for the split decision
 * @cpa: CPA operation whose page count is limited to the mapping
 * @sd: Split state containing the address and expected page table entry
 *
 * Revalidate the mapping, calculate its size and mask, and limit the page
 * count for the preservation check. The caller must hold cpa_lock and any
 * architecture-specific page table lock through this call and the update.
 *
 * Return: 0 when the split state is ready, or 1 when the mapping changed
 * and the caller must retry without using the old entry.
 */
int cpa_prepare_split(struct cpa_data *cpa, struct cpa_split_data *sd)
{
	unsigned long address = sd->address;
	unsigned long numpages, lpaddr;
	int ret;

	ret = cpa_revalidate_mapping(cpa, sd);
	if (ret)
		return ret;

	sd->psize = pgtable_level_size(sd->level);
	sd->pmask = pgtable_level_mask(sd->level);

	/*
	 * Calculate the number of pages, which fit into this large
	 * page starting at address:
	 */
	lpaddr = (address + sd->psize) & sd->pmask;
	numpages = (lpaddr - address) >> PAGE_SHIFT;
	if (numpages < cpa->numpages)
		cpa->numpages = numpages;

	return 0;
}

static int should_split_large_page(struct cpa_data *cpa,
				   struct cpa_split_data *sd)
{
	if (cpa->req & CPA_REQ_SPLIT)
		return 1;

	return arch_should_split_large_page(cpa, sd);
}

static int split_large_page(struct cpa_data *cpa, struct cpa_split_data *sd)
{
	int ret;

	spin_unlock(&cpa_lock);
	if (cpa->state & CPA_ST_MM_LOCKED)
		mmap_read_unlock(&init_mm);
	sd->pbase = pte_alloc_one_kernel(&init_mm);
	if (cpa->state & CPA_ST_MM_LOCKED)
		mmap_read_lock(&init_mm);
	spin_lock(&cpa_lock);
	if (!sd->pbase)
		return -ENOMEM;

	ret = arch_split_large_page(cpa, sd);
	if (ret)
		pte_free_kernel(&init_mm, sd->pbase);

	return ret;
}

static int cpa_handle_large_page(struct cpa_data *cpa, pte_t *kpte,
				 unsigned long address)
{
	struct cpa_split_data sd = {
		.address = address,
		.kpte = kpte,
	};
	int do_split, ret;

	/*
	 * Check, whether we can keep the large page intact
	 * and just change the pte:
	 */
	do_split = should_split_large_page(cpa, &sd);
	/*
	 * When the range fits into the existing large page, no split is
	 * required.
	 * should_split_large_page() updated the large page attributes and
	 * cpa->numpages and cpa->pfn.
	 */
	if (do_split <= 0)
		return do_split;

	/*
	 * We have to split the large page:
	 */
	ret = split_large_page(cpa, &sd);
	if (ret < 0)
		return ret;

	return do_split;
}

static int __change_page_attr(struct cpa_data *cpa)
{
	unsigned long address;
	int split_res;
	enum pgtable_level level;
	pte_t *kpte, old_pte;
	bool nx, rw;

	address = cpa_addr(cpa, cpa->curpage);
repeat:
	kpte = lookup_address_cpa(cpa, address, &level, &nx, &rw);
	if (!kpte)
		return arch_cpa_process_fault(cpa, address);

	old_pte = *kpte;
	if (pte_none(old_pte))
		return arch_cpa_process_fault(cpa, address);

	if (level == PGTABLE_LEVEL_PTE) {
		int ret = arch_change_pte(cpa, address, kpte, old_pte, nx, rw);

		if (ret)
			return ret;

		cpa->numpages = 1;
		return 0;
	}

	/*
	 * The address maps a large page. Try to keep it, otherwise split it
	 * up and retry on the freshly installed smaller mapping.
	 */
	split_res = cpa_handle_large_page(cpa, kpte, address);
	if (split_res > 0)
		goto repeat;

	return split_res;
}

int __change_page_attr_set_clr(struct cpa_data *cpa)
{
	unsigned long numpages = cpa->numpages;
	unsigned long rempages = numpages;
	int ret = 0;

	/*
	 * No changes, easy!
	 */
	if (!(pgprot_val(cpa->mask_set) | pgprot_val(cpa->mask_clr)) &&
	    !(cpa->req & CPA_REQ_SPLIT))
		return ret;

	while (rempages) {
		/*
		 * Store the remaining nr of pages for the large page
		 * preservation check.
		 */
		cpa->numpages = rempages;
		/* for array changes, we can't use large page */
		if (cpa->req & (CPA_REQ_ARRAY | CPA_REQ_PAGES_ARRAY))
			cpa->numpages = 1;

		scoped_guard(spinlock, &cpa_lock)
			ret = __change_page_attr(cpa);
		if (ret)
			goto out;

		if (!(cpa->state & CPA_ST_ALIAS) &&
		    !(cpa->req & CPA_REQ_NO_ALIAS) &&
		    arch_cpa_should_update_alias(cpa_addr(cpa, cpa->curpage),
						 cpa->pfn)) {
			ret = arch_cpa_process_alias(cpa);
			if (ret)
				goto out;
		}

		/*
		 * Adjust the number of pages with the result of the
		 * CPA operation. Either a large page has been
		 * preserved or a single page update happened.
		 */
		BUG_ON(cpa->numpages > rempages || !cpa->numpages);
		rempages -= cpa->numpages;
		cpa->curpage += cpa->numpages;
	}

out:
	/* Restore the original numpages */
	cpa->numpages = numpages;
	return ret;
}

int change_page_attr_set_clr(unsigned long *addr, int numpages,
			     pgprot_t mask_set, pgprot_t mask_clr,
			     unsigned int request,
			     struct page **pages)
{
	struct cpa_data cpa;
	int err;

	memset(&cpa, 0, sizeof(cpa));

	/*
	 * Check, if we are requested to set a not supported
	 * feature.  Clearing non-supported features is OK.
	 */
	mask_set = canon_pgprot(mask_set);

	if (!pgprot_val(mask_set) && !pgprot_val(mask_clr) &&
	    !(request & CPA_REQ_SPLIT))
		return 0;

	/* Ensure we are PAGE_SIZE aligned */
	if (request & CPA_REQ_ARRAY) {
		int i;

		for (i = 0; i < numpages; i++) {
			if (addr[i] & ~PAGE_MASK) {
				addr[i] &= PAGE_MASK;
				WARN_ON_ONCE(1);
			}
		}
	} else if (!(request & CPA_REQ_PAGES_ARRAY)) {
		/*
		 * CPA_REQ_PAGES_ARRAY implies it is aligned.
		 * No need to check in that case
		 */
		if (*addr & ~PAGE_MASK) {
			*addr &= PAGE_MASK;
			/*
			 * People should not be passing in unaligned addresses:
			 */
			WARN_ON_ONCE(1);
		}
	}

	/* Must avoid aliasing mappings in the highmem code */
	kmap_flush_unused();

	vm_unmap_aliases();

	cpa.vaddr = addr;
	cpa.pages = pages;
	cpa.numpages = numpages;
	cpa.mask_set = mask_set;
	cpa.mask_clr = mask_clr;
	cpa.req = request;
	cpa.curpage = 0;

	err = arch_cpa_prepare(&cpa);
	if (err)
		return err;

	/* Avoid race with concurrent CPA collapse. */
	cpa.state |= CPA_ST_MM_LOCKED;
	scoped_guard(mmap_read_lock, &init_mm)
		err = __change_page_attr_set_clr(&cpa);
	cpa.state &= ~CPA_ST_MM_LOCKED;

	arch_cpa_finish(&cpa, err);

	return err;
}

static int cpa_change_memory(unsigned long addr, int numpages,
			     enum cpa_op op)
{
	struct cpa_op_desc desc = arch_cpa_op_descs[op];

	if (numpages < 0)
		return -EINVAL;

	if (!desc.supported)
		return -EOPNOTSUPP;

	return change_page_attr_set_clr(&addr, numpages, desc.mask_set,
					desc.mask_clr, desc.flags, NULL);
}

int set_memory_ro(unsigned long addr, int numpages)
{
	return cpa_change_memory(addr, numpages, CPA_SET_RO);
}

int set_memory_rw(unsigned long addr, int numpages)
{
	return cpa_change_memory(addr, numpages, CPA_SET_RW);
}

int set_memory_x(unsigned long addr, int numpages)
{
	return cpa_change_memory(addr, numpages, CPA_SET_X);
}

int set_memory_nx(unsigned long addr, int numpages)
{
	return cpa_change_memory(addr, numpages, CPA_SET_NX);
}

#ifdef CONFIG_ARCH_HAS_SET_DIRECT_MAP
static int cpa_change_direct_map(struct page *page, unsigned int nr,
				 enum cpa_op op)
{
	unsigned long addr = (unsigned long)page_address(page);
	struct cpa_op_desc desc = arch_cpa_op_descs[op];
	struct cpa_data cpa = {
		.vaddr = &addr,
		.numpages = nr,
	};
	int ret;

	if (!desc.supported)
		return -EOPNOTSUPP;

	cpa.mask_set = desc.mask_set;
	cpa.mask_clr = desc.mask_clr;
	cpa.req = desc.flags;

	ret = arch_cpa_prepare(&cpa);
	if (ret)
		return ret;

	ret = __change_page_attr_set_clr(&cpa);

	arch_cpa_finish_direct_map(&cpa);

	return ret;
}

int set_direct_map_invalid_noflush(struct page *page, unsigned int nr)
{
	return cpa_change_direct_map(page, nr, CPA_SET_INVALID);
}

int set_direct_map_default_noflush(struct page *page, unsigned int nr)
{
	return cpa_change_direct_map(page, nr, CPA_SET_DEFAULT);
}
#endif

/*
 * The testcases use internal knowledge of the implementation that shouldn't
 * be exposed to the rest of the kernel. Include these directly here.
 */
#ifdef CONFIG_CPA_DEBUG
#include "cpa-test.c"
#endif
