// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2002 Andi Kleen, SuSE Labs.
 * Thanks to Ben LaHaise for precious feedback.
 */
#include <linux/highmem.h>
#include <linux/memblock.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/pfn.h>
#include <linux/percpu.h>
#include <linux/gfp.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/libnvdimm.h>
#include <linux/vmstat.h>
#include <linux/kernel.h>
#include <linux/cc_platform.h>
#include <linux/pageattr.h>
#include <linux/set_memory.h>
#include <linux/memregion.h>
#include <linux/cleanup.h>

#include <asm/e820/api.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <linux/uaccess.h>
#include <asm/pgalloc.h>
#include <asm/proto.h>
#include <asm/memtype.h>
#include <asm/mtrr.h>

#include "../mm_internal.h"

static inline pgprot_t cachemode2pgprot(enum page_cache_mode pcm)
{
	return __pgprot(cachemode2protval(pcm));
}

#ifdef CONFIG_PROC_FS
static unsigned long direct_pages_count[PG_LEVEL_NUM];

void update_page_count(int level, unsigned long pages)
{
	/* Protect against CPA */
	guard(spinlock)(&pgd_lock);
	direct_pages_count[level] += pages;
}

static void split_page_count(int level)
{
	if (direct_pages_count[level] == 0)
		return;

	direct_pages_count[level]--;
	if (system_state == SYSTEM_RUNNING) {
		if (level == PG_LEVEL_2M)
			count_vm_event(DIRECT_MAP_LEVEL2_SPLIT);
		else if (level == PG_LEVEL_1G)
			count_vm_event(DIRECT_MAP_LEVEL3_SPLIT);
	}
	direct_pages_count[level - 1] += PTRS_PER_PTE;
}

static void collapse_page_count(int level)
{
	direct_pages_count[level]++;
	if (system_state == SYSTEM_RUNNING) {
		if (level == PG_LEVEL_2M)
			count_vm_event(DIRECT_MAP_LEVEL2_COLLAPSE);
		else if (level == PG_LEVEL_1G)
			count_vm_event(DIRECT_MAP_LEVEL3_COLLAPSE);
	}
	direct_pages_count[level - 1] -= PTRS_PER_PTE;
}

void arch_report_meminfo(struct seq_file *m)
{
	seq_printf(m, "DirectMap4k:    %8lu kB\n",
			direct_pages_count[PG_LEVEL_4K] << 2);
#if defined(CONFIG_X86_64) || defined(CONFIG_X86_PAE)
	seq_printf(m, "DirectMap2M:    %8lu kB\n",
			direct_pages_count[PG_LEVEL_2M] << 11);
#else
	seq_printf(m, "DirectMap4M:    %8lu kB\n",
			direct_pages_count[PG_LEVEL_2M] << 12);
#endif
	if (direct_gbpages)
		seq_printf(m, "DirectMap1G:    %8lu kB\n",
			direct_pages_count[PG_LEVEL_1G] << 20);
}
#else
static inline void split_page_count(int level) { }
static inline void collapse_page_count(int level) { }
#endif

static inline int
within(unsigned long addr, unsigned long start, unsigned long end)
{
	return addr >= start && addr < end;
}

#ifdef CONFIG_X86_64

static inline int
within_inclusive(unsigned long addr, unsigned long start, unsigned long end)
{
	return addr >= start && addr <= end;
}

/*
 * The kernel image is mapped into two places in the virtual address space
 * (addresses without KASLR, of course):
 *
 * 1. The kernel direct map (0xffff880000000000)
 * 2. The "high kernel map" (0xffffffff81000000)
 *
 * We actually execute out of #2. If we get the address of a kernel symbol, it
 * points to #2, but almost all physical-to-virtual translations point to #1.
 *
 * This is so that we can have both a directmap of all physical memory *and*
 * take full advantage of the limited (s32) immediate addressing range (2G)
 * of x86_64.
 *
 * See Documentation/arch/x86/x86_64/mm.rst for more detail.
 */

static inline unsigned long highmap_start_pfn(void)
{
	return __pa_symbol(_text) >> PAGE_SHIFT;
}

static inline unsigned long highmap_end_pfn(void)
{
	/* Do not reference physical address outside the kernel. */
	return __pa_symbol(roundup(_brk_end, PMD_SIZE) - 1) >> PAGE_SHIFT;
}

#endif

/*
 * See set_mce_nospec().
 *
 * Machine check recovery code needs to change cache mode of poisoned pages to
 * UC to avoid speculative access logging another error. But passing the
 * address of the 1:1 mapping to set_memory_uc() is a fine way to encourage a
 * speculative access. So we cheat and flip the top bit of the address. This
 * works fine for the code that updates the page tables. But at the end of the
 * process we need to flush the TLB and cache and the non-canonical address
 * causes a #GP fault when used by the INVLPG and CLFLUSH instructions.
 *
 * But in the common case we already have a canonical address. This code
 * will fix the top bit if needed and is a no-op otherwise.
 */
static inline unsigned long fix_addr(unsigned long addr)
{
#ifdef CONFIG_X86_64
	return (long)(addr << 1) >> 1;
#else
	return addr;
#endif
}

/*
 * Flushing functions
 */

static void clflush_cache_range_opt(void *vaddr, unsigned int size)
{
	const unsigned long clflush_size = boot_cpu_data.x86_clflush_size;
	void *p = (void *)((unsigned long)vaddr & ~(clflush_size - 1));
	void *vend = vaddr + size;

	if (p >= vend)
		return;

	for (; p < vend; p += clflush_size)
		clflushopt(p);
}

/**
 * clflush_cache_range - flush a cache range with clflush
 * @vaddr:	virtual start address
 * @size:	number of bytes to flush
 *
 * CLFLUSHOPT is an unordered instruction which needs fencing with MFENCE or
 * SFENCE to avoid ordering issues.
 */
void clflush_cache_range(void *vaddr, unsigned int size)
{
	mb();
	clflush_cache_range_opt(vaddr, size);
	mb();
}
EXPORT_SYMBOL_GPL(clflush_cache_range);

#ifdef CONFIG_ARCH_HAS_PMEM_API
void arch_invalidate_pmem(void *addr, size_t size)
{
	clflush_cache_range(addr, size);
}
EXPORT_SYMBOL_GPL(arch_invalidate_pmem);
#endif

#ifdef CONFIG_ARCH_HAS_CPU_CACHE_INVALIDATE_MEMREGION
bool cpu_cache_has_invalidate_memregion(void)
{
	return !cpu_feature_enabled(X86_FEATURE_HYPERVISOR);
}
EXPORT_SYMBOL_NS_GPL(cpu_cache_has_invalidate_memregion, "DEVMEM");

int cpu_cache_invalidate_memregion(phys_addr_t start, size_t len)
{
	if (WARN_ON_ONCE(!cpu_cache_has_invalidate_memregion()))
		return -ENXIO;
	wbinvd_on_all_cpus();
	return 0;
}
EXPORT_SYMBOL_NS_GPL(cpu_cache_invalidate_memregion, "DEVMEM");
#endif

static void __cpa_flush_all(void *arg)
{
	unsigned long cache = (unsigned long)arg;

	/*
	 * Flush all to work around Errata in early athlons regarding
	 * large page flushing.
	 */
	__flush_tlb_all();

	if (cache && boot_cpu_data.x86 >= 4)
		wbinvd();
}

static void cpa_flush_all(unsigned long cache)
{
	BUG_ON(irqs_disabled() && !early_boot_irqs_disabled);

	on_each_cpu(__cpa_flush_all, (void *) cache, 1);
}
/*
 * Lookup the page table entry for a virtual address in a specific pgd.
 * Return a pointer to the entry (or NULL if the entry does not exist),
 * the level of the entry, and the effective NX and RW bits of all
 * page table levels.
 */
pte_t *lookup_address_in_pgd_attr(pgd_t *pgd, unsigned long address,
				  unsigned int *level, bool *nx, bool *rw)
{
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	*level = PG_LEVEL_256T;
	*nx = false;
	*rw = true;

	if (pgd_none(*pgd))
		return NULL;

	*level = PG_LEVEL_512G;
	*nx |= pgd_flags(*pgd) & _PAGE_NX;
	*rw &= !!(pgd_flags(*pgd) & _PAGE_RW);

	p4d = p4d_offset(pgd, address);
	if (p4d_none(*p4d))
		return NULL;

	if (p4d_leaf(*p4d) || !p4d_present(*p4d))
		return (pte_t *)p4d;

	*level = PG_LEVEL_1G;
	*nx |= p4d_flags(*p4d) & _PAGE_NX;
	*rw &= !!(p4d_flags(*p4d) & _PAGE_RW);

	pud = pud_offset(p4d, address);
	if (pud_none(*pud))
		return NULL;

	if (pud_leaf(*pud) || !pud_present(*pud))
		return (pte_t *)pud;

	*level = PG_LEVEL_2M;
	*nx |= pud_flags(*pud) & _PAGE_NX;
	*rw &= !!(pud_flags(*pud) & _PAGE_RW);

	pmd = pmd_offset(pud, address);
	if (pmd_none(*pmd))
		return NULL;

	if (pmd_leaf(*pmd) || !pmd_present(*pmd))
		return (pte_t *)pmd;

	*level = PG_LEVEL_4K;
	*nx |= pmd_flags(*pmd) & _PAGE_NX;
	*rw &= !!(pmd_flags(*pmd) & _PAGE_RW);

	return pte_offset_kernel(pmd, address);
}

/*
 * Lookup the page table entry for a virtual address in a specific pgd.
 * Return a pointer to the entry and the level of the mapping.
 */
pte_t *lookup_address_in_pgd(pgd_t *pgd, unsigned long address,
			     unsigned int *level)
{
	bool nx, rw;

	return lookup_address_in_pgd_attr(pgd, address, level, &nx, &rw);
}

/*
 * Lookup the page table entry for a virtual address. Return a pointer
 * to the entry and the level of the mapping.
 *
 * Note: the function returns p4d, pud or pmd either when the entry is marked
 * large or when the present bit is not set. Otherwise it returns NULL.
 */
pte_t *lookup_address(unsigned long address, unsigned int *level)
{
	return lookup_address_in_pgd(pgd_offset_k(address), address, level);
}
EXPORT_SYMBOL_GPL(lookup_address);

/*
 * Lookup the PMD entry for a virtual address. Return a pointer to the entry
 * or NULL if not present.
 */
pmd_t *lookup_pmd_address(unsigned long address)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;

	pgd = pgd_offset_k(address);
	if (pgd_none(*pgd))
		return NULL;

	p4d = p4d_offset(pgd, address);
	if (p4d_none(*p4d) || p4d_leaf(*p4d) || !p4d_present(*p4d))
		return NULL;

	pud = pud_offset(p4d, address);
	if (pud_none(*pud) || pud_leaf(*pud) || !pud_present(*pud))
		return NULL;

	return pmd_offset(pud, address);
}

/*
 * This is necessary because __pa() does not work on some
 * kinds of memory, like vmalloc() or the alloc_remap()
 * areas on 32-bit NUMA systems.  The percpu areas can
 * end up in this kind of memory, for instance.
 *
 * Note that as long as the PTEs are well-formed with correct PFNs, this
 * works without checking the PRESENT bit in the leaf PTE.  This is unlike
 * the similar vmalloc_to_page() and derivatives.  Callers may depend on
 * this behavior.
 *
 * This could be optimized, but it is only used in paths that are not perf
 * sensitive, and keeping it unoptimized should increase the testing coverage
 * for the more obscure platforms.
 */
phys_addr_t slow_virt_to_phys(void *__virt_addr)
{
	unsigned long virt_addr = (unsigned long)__virt_addr;
	phys_addr_t phys_addr;
	unsigned long offset;
	enum pg_level level;
	pte_t *pte;

	pte = lookup_address(virt_addr, &level);
	BUG_ON(!pte);

	/*
	 * pXX_pfn() returns unsigned long, which must be cast to phys_addr_t
	 * before being left-shifted PAGE_SHIFT bits -- this trick is to
	 * make 32-PAE kernel work correctly.
	 */
	switch (level) {
	case PG_LEVEL_1G:
		phys_addr = (phys_addr_t)pud_pfn(*(pud_t *)pte) << PAGE_SHIFT;
		offset = virt_addr & ~PUD_MASK;
		break;
	case PG_LEVEL_2M:
		phys_addr = (phys_addr_t)pmd_pfn(*(pmd_t *)pte) << PAGE_SHIFT;
		offset = virt_addr & ~PMD_MASK;
		break;
	default:
		phys_addr = (phys_addr_t)pte_pfn(*pte) << PAGE_SHIFT;
		offset = virt_addr & ~PAGE_MASK;
	}

	return (phys_addr_t)(phys_addr | offset);
}
EXPORT_SYMBOL_GPL(slow_virt_to_phys);
static void cpa_clflush_page(unsigned long addr)
{
	unsigned int level;
	pte_t *pte = lookup_address(addr, &level);

	/*
	 * Only flush present addresses:
	 */
	if (pte && (pte_val(*pte) & _PAGE_PRESENT))
		clflush_cache_range_opt((void *)fix_addr(addr), PAGE_SIZE);
}

static void cpa_flush_cache(unsigned long addr, unsigned long numpages)
{
	unsigned long i;

	mb();
	for (i = 0; i < numpages; i++)
		cpa_clflush_page(addr + i * PAGE_SIZE);
	mb();
}

static void cpa_flush_range(unsigned long addr, unsigned long numpages,
			    bool cache)
{
	if (cache && !cpu_feature_enabled(X86_FEATURE_CLFLUSH)) {
		cpa_flush_all(cache);
		return;
	}

	flush_tlb_kernel_range(fix_addr(addr),
			       fix_addr(addr + numpages * PAGE_SIZE));

	if (cache)
		cpa_flush_cache(addr, numpages);
}

static void cpa_unmap_aliases(void)
{
	/* Must avoid aliasing mappings in the highmem code */
	kmap_flush_unused();

	vm_unmap_aliases();
}

static bool cpa_direct_map_addr(unsigned long addr)
{
	return within(fix_addr(addr), PAGE_OFFSET,
		      PAGE_OFFSET + (max_pfn_mapped << PAGE_SHIFT));
}

static pgprot_t pgprot_clear_protnone_bits(pgprot_t prot)
{
	/*
	 * _PAGE_GLOBAL means "global page" for present PTEs.
	 * But, it is also used to indicate _PAGE_PROTNONE
	 * for non-present PTEs.
	 *
	 * This ensures that a _PAGE_GLOBAL PTE going from
	 * present to non-present is not confused as
	 * _PAGE_PROTNONE.
	 */
	if (!(pgprot_val(prot) & _PAGE_PRESENT))
		pgprot_val(prot) &= ~_PAGE_GLOBAL;

	return prot;
}

void arch_cpa_prot(enum cpa_prot_op op, pgprot_t *set, pgprot_t *clr)
{
	pgprotval_t s = 0, c = 0;

	switch (op) {
	case CPA_PROT_RO:
		c = _PAGE_RW | _PAGE_DIRTY;
		break;
	case CPA_PROT_RW:
		s = _PAGE_RW;
		break;
	case CPA_PROT_X:
		c = _PAGE_NX;
		break;
	case CPA_PROT_NX:
		s = _PAGE_NX;
		break;
	case CPA_PROT_NP:
		c = _PAGE_PRESENT;
		break;
	case CPA_PROT_P:
		s = _PAGE_PRESENT;
		break;
	case CPA_PROT_INVALID:
		c = _PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY;
		break;
	case CPA_PROT_DEFAULT:
		s = _PAGE_PRESENT | _PAGE_RW;
		break;
	}

	*set = __pgprot(s & __supported_pte_mask);
	*clr = __pgprot(c & __supported_pte_mask);
}

/*
 * Large leaves have PSE set even when they are not present, so that their
 * pfn can be decoded.
 */
static pgprot_t cpa_large_prot(pgprot_t prot)
{
	return __pgprot(protval_4k_2_large(pgprot_val(prot)) | _PAGE_PSE);
}

void arch_cpa_read_leaf(struct cpa_leaf *leaf)
{
	pte_t pte;
	pmd_t pmd;
	pud_t pud;

	switch (leaf->level) {
	case PGTABLE_LEVEL_PTE:
		pte = ptep_get(leaf->entry);
		leaf->pfn = pte_pfn(pte);
		leaf->prot = __pgprot(pte_flags(pte));
		break;
	case PGTABLE_LEVEL_PMD:
		pmd = pmdp_get(leaf->entry);
		leaf->pfn = pmd_pfn(pmd);
		leaf->prot = __pgprot(protval_large_2_4k(pmd_flags(pmd)));
		break;
	default:
		pud = pudp_get(leaf->entry);
		leaf->pfn = pud_pfn(pud);
		leaf->prot = __pgprot(protval_large_2_4k(pud_flags(pud)));
		break;
	}
}

/*
 * Set the new pmd in all the pgds we know about:
 */
static void cpa_set_pmd(struct cpa_req *req, pmd_t *pmdp, unsigned long addr,
			pmd_t pmd)
{
	pte_t pte = __pte(pmd_val(pmd));
	struct ptdesc *ptdesc;

	if (!IS_ENABLED(CONFIG_X86_32) || req->pgd) {
		set_pte_atomic((pte_t *)pmdp, pte);
		return;
	}

	guard(spinlock)(&pgd_lock);

	/* change init_mm */
	set_pte_atomic((pte_t *)pmdp, pte);

	list_for_each_entry(ptdesc, &pgd_list, pt_list) {
		pgd_t *pgd;
		p4d_t *p4d;
		pud_t *pud;

		pgd = (pgd_t *)ptdesc_address(ptdesc) + pgd_index(addr);
		p4d = p4d_offset(pgd, addr);
		pud = pud_offset(p4d, addr);
		set_pte_atomic((pte_t *)pmd_offset(pud, addr), pte);
	}
}

void arch_cpa_write_leaf(struct cpa_req *req, struct cpa_leaf *leaf,
			 pgprot_t prot)
{
	switch (leaf->level) {
	case PGTABLE_LEVEL_PTE:
		set_pte_atomic(leaf->entry, pfn_pte(leaf->pfn, prot));
		break;
	case PGTABLE_LEVEL_PMD:
		cpa_set_pmd(req, leaf->entry, leaf->start,
			    pfn_pmd(leaf->pfn, cpa_large_prot(prot)));
		break;
	default:
		set_pud(leaf->entry, pfn_pud(leaf->pfn, cpa_large_prot(prot)));
		break;
	}
}

/*
 * Certain areas of memory on x86 require very specific protection flags,
 * for example the BIOS area or kernel text. Callers don't always get this
 * right (again, ioremap() on BIOS memory is not uncommon) so the requests
 * that set a forbidden bit are fixed up.
 *
 * Return false if [@start, @end) partially overlaps [@rstart, @rend), so
 * that the leaf is split and the parts are checked separately.
 */
static bool cpa_protect(pgprotval_t *prot, pgprotval_t forbidden,
			unsigned long start, unsigned long end,
			unsigned long rstart, unsigned long rend,
			const char *txt)
{
	if (!(*prot & forbidden) || end <= rstart || rend <= start)
		return true;

	if (start < rstart || end > rend)
		return false;

	pr_warn_ratelimited("CPA protect %10s: 0x%016lx - 0x%016lx req %016llx prevent %016llx\n",
			    txt, start, end - 1, (unsigned long long)*prot,
			    (unsigned long long)forbidden);

	*prot &= ~forbidden;
	return true;
}

/*
 * Protect kernel text against becoming non executable by forbidding
 * _PAGE_NX.  This protects only the high kernel mapping (_text -> _etext)
 * out of which the kernel actually executes.  Do not protect the low
 * mapping.
 *
 * This does not cover __inittext since that is gone after boot.
 */
static bool protect_kernel_text(pgprotval_t *prot, unsigned long start,
				unsigned long end)
{
	return cpa_protect(prot, _PAGE_NX, start, end, (unsigned long)_text,
			   PAGE_ALIGN((unsigned long)_etext), "Text NX");
}

#ifdef CONFIG_PCI_BIOS
/*
 * The BIOS area between 640k and 1Mb needs to be executable for PCI BIOS
 * based config access (CONFIG_PCI_GOBIOS) support.
 */
static bool protect_pci_bios(pgprotval_t *prot, unsigned long spfn,
			     unsigned long epfn)
{
	if (!pcibios_enabled)
		return true;

	return cpa_protect(prot, _PAGE_NX, spfn, epfn, PFN_DOWN(BIOS_BEGIN),
			   PFN_UP(BIOS_END), "PCIBIOS NX");
}
#else
static bool protect_pci_bios(pgprotval_t *prot, unsigned long spfn,
			     unsigned long epfn)
{
	return true;
}
#endif

/*
 * The .rodata section needs to be read-only. Using the pfn catches all
 * aliases.  This also includes __ro_after_init, so do not enforce until
 * kernel_set_to_readonly is true.
 */
static bool protect_rodata(pgprotval_t *prot, unsigned long spfn,
			   unsigned long epfn)
{
	if (!kernel_set_to_readonly)
		return true;

	return cpa_protect(prot, _PAGE_RW | _PAGE_DIRTY, spfn, epfn,
			   PFN_DOWN(__pa_symbol(__start_rodata)),
			   PFN_DOWN(__pa_symbol(__end_rodata)), "Rodata RO");
}

/*
 * Validate strict W^X semantics.
 */
static void verify_rwx(struct cpa_req *req, pgprotval_t old, pgprotval_t new,
		       unsigned long start, unsigned long end,
		       unsigned long pfn)
{
	unsigned int level;
	bool nx, rw;
	pgd_t *pgd;

	/*
	 * 32-bit has some unfixable W+X issues, like EFI code
	 * and writeable data being in the same page.  Disable
	 * detection and enforcement there.
	 */
	if (IS_ENABLED(CONFIG_X86_32))
		return;

	/* Only verify when NX is supported: */
	if (!(__supported_pte_mask & _PAGE_NX))
		return;

	if (!((old ^ new) & (_PAGE_RW | _PAGE_NX)))
		return;

	if ((new & (_PAGE_RW | _PAGE_NX)) != _PAGE_RW)
		return;

	/*
	 * The kernel text is RWX until mark_rodata_ro() and the entire kernel
	 * page table is verified after the text is protected, so there is no
	 * need to warn.
	 */
	if (!kernel_set_to_readonly)
		return;

	/* Non-leaf translation entries can disable writing or execution. */
	pgd = req->pgd ? pgd_offset_pgd(req->pgd, start) : pgd_offset_k(start);
	lookup_address_in_pgd_attr(pgd, start, &level, &nx, &rw);
	if (!rw || nx)
		return;

	WARN_ONCE(1, "CPA detected W^X violation: %016llx -> %016llx range: 0x%016lx - 0x%016lx PFN %lx\n",
		  (unsigned long long)old, (unsigned long long)new,
		  start, end - 1, pfn);
}

bool arch_cpa_new_prot(struct cpa_req *req, struct cpa_range *range,
		       struct cpa_leaf *leaf, unsigned long start,
		       unsigned long end, pgprot_t *prot)
{
	pgprotval_t set = pgprot_val(range->set) & __supported_pte_mask;
	pgprotval_t old = pgprot_val(leaf->prot);
	pgprotval_t new = (old & ~pgprot_val(range->clr)) | set;
	unsigned long pfn = leaf->pfn + ((start - leaf->start) >> PAGE_SHIFT);
	unsigned long epfn = pfn + ((end - start) >> PAGE_SHIFT);
	bool uniform = true;

	/*
	 * There is no point in checking RW/NX conflicts when the requested
	 * mapping is setting the page !PRESENT.
	 */
	if (new & _PAGE_PRESENT) {
		if (set & _PAGE_NX) {
			uniform &= protect_kernel_text(&new, start, end);
			uniform &= protect_pci_bios(&new, pfn, epfn);
		}
		if (set & _PAGE_RW)
			uniform &= protect_rodata(&new, pfn, epfn);
		if (!uniform)
			return false;
	}

	verify_rwx(req, old, new, start, end, pfn);

	*prot = pgprot_clear_protnone_bits(__pgprot(new));
	return true;
}

int arch_cpa_check_range(struct cpa_req *req)
{
	if (!req->pgd && !(req->flags & (CPA_NOFLUSH | CPA_ATOMIC)))
		cpa_unmap_aliases();

	return 0;
}

int arch_cpa_split(struct cpa_req *req, struct cpa_leaf *leaf, void *table)
{
	unsigned long table_pfn = __pa(table) >> PAGE_SHIFT;
	unsigned int i;

	if (leaf->level == PGTABLE_LEVEL_PMD) {
		pte_t *ptep = table;

		paravirt_alloc_pte(&init_mm, table_pfn);
		for (i = 0; i < PTRS_PER_PTE; i++)
			set_pte(ptep + i, pfn_pte(leaf->pfn + i, leaf->prot));

		/*
		 * We use the standard kernel pagetable protections for the new
		 * pagetable protections, the actual ptes set above control the
		 * primary protection behavior:
		 */
		cpa_set_pmd(req, leaf->entry, leaf->start,
			    __pmd(__pa(table) | _KERNPG_TABLE));
	} else {
		unsigned long step = PMD_SIZE >> PAGE_SHIFT;
		pgprot_t prot = cpa_large_prot(leaf->prot);
		pmd_t *pmdp = table;

		paravirt_alloc_pmd(&init_mm, table_pfn);
		for (i = 0; i < PTRS_PER_PMD; i++)
			set_pmd(pmdp + i, pfn_pmd(leaf->pfn + i * step, prot));

		set_pud(leaf->entry, __pud(__pa(table) | _KERNPG_TABLE));
	}

	/*
	 * Do a global flush tlb after splitting the large page
	 * and before we do the actual change page attribute in the PTE.
	 *
	 * Without this, we violate the TLB application note, that says:
	 * "The TLBs may contain both ordinary and large-page
	 *  translations for a 4-KByte range of linear addresses. This
	 *  may occur if software modifies the paging structures so that
	 *  the page size used for the address range changes. If the two
	 *  translations differ with respect to page frame or attributes
	 *  (e.g., permissions), processor behavior is undefined and may
	 *  be implementation-specific."
	 */
	flush_tlb_all();

	if (!req->pgd && cpa_direct_map_addr(leaf->start)) {
		guard(spinlock)(&pgd_lock);
		split_page_count(leaf->level == PGTABLE_LEVEL_PMD ?
				 PG_LEVEL_2M : PG_LEVEL_1G);
	}

	return 0;
}

bool arch_cpa_can_collapse(struct cpa_req *req, enum pgtable_level level)
{
	if (level == PGTABLE_LEVEL_PUD)
		return direct_gbpages;

	/* Xen PV does not support large pages */
	return cpu_feature_enabled(X86_FEATURE_PSE);
}

/*
 * Hot-remove does not split leaves that map more than one memory section,
 * so they must not map memory that can be removed. Memory present at boot
 * cannot be removed.
 */
static bool cpa_maps_removable_memory(struct cpa_leaf *leaf)
{
#ifdef CONFIG_MEMORY_HOTREMOVE
	unsigned long end = leaf->pfn + (leaf->size >> PAGE_SHIFT);
	unsigned long pfn;

	if (leaf->size <= PAGES_PER_SECTION << PAGE_SHIFT ||
	    !cpa_direct_map_addr(leaf->start))
		return false;

	for (pfn = leaf->pfn; pfn < end; pfn += PAGES_PER_SECTION) {
		struct mem_section *ms = __pfn_to_section(pfn);

		if (!ms || !early_section(ms))
			return true;
	}
#endif
	return false;
}

bool arch_cpa_collapse(struct cpa_req *req, struct cpa_leaf *leaf)
{
	pgprotval_t prot = pgprot_val(leaf->prot);
	phys_addr_t phys = PFN_PHYS(leaf->pfn);
	unsigned long last = leaf->start + leaf->size - 1;
	u8 uniform;

	/* The page is 4k intentionally */
	if (!(prot & _PAGE_PRESENT) || (prot & _PAGE_KERNEL_4K))
		return false;

	/* PTI shares tables of the kernel image with the user page tables */
	if (leaf->start <= (unsigned long)_end - 1 &&
	    (unsigned long)_text <= last)
		return false;

	mtrr_type_lookup(phys, phys + leaf->size, &uniform);
	if (!uniform)
		return false;

	if (cpa_maps_removable_memory(leaf))
		return false;

	/* the TLB must not have small entries with different attributes */
	if (req->flags & CPA_NOFLUSH)
		flush_tlb_all();

	if (leaf->level == PGTABLE_LEVEL_PMD)
		cpa_set_pmd(req, leaf->entry, leaf->start,
			    pfn_pmd(leaf->pfn, cpa_large_prot(leaf->prot)));
	else
		set_pud(leaf->entry,
			pfn_pud(leaf->pfn, cpa_large_prot(leaf->prot)));

	/* the table is freed after return, drop it from the paging caches */
	flush_tlb_all();

	if (cpa_direct_map_addr(leaf->start)) {
		guard(spinlock)(&pgd_lock);
		collapse_page_count(leaf->level == PGTABLE_LEVEL_PMD ?
				    PG_LEVEL_2M : PG_LEVEL_1G);
	}

	return true;
}

bool arch_cpa_get_alias(struct cpa_req *req, struct cpa_range *range,
			unsigned long addr, unsigned long pfn,
			unsigned long nr, unsigned int idx,
			struct cpa_range *alias)
{
	/* Directmap always has NX set, do not modify. */
	alias->set = __pgprot(pgprot_val(range->set) & ~_PAGE_NX);
	alias->clr = __pgprot(pgprot_val(range->clr) & ~_PAGE_NX);

	if (!pgprot_val(alias->set) && !pgprot_val(alias->clr) &&
	    !(req->flags & CPA_SPLIT))
		return false;

	if (!pfn_range_is_mapped(pfn, pfn + nr))
		return false;

	/*
	 * No need to redo, when the primary call touched the direct
	 * mapping already:
	 */
	if (!cpa_direct_map_addr(addr) && !idx--) {
		alias->start = (unsigned long)__va(PFN_PHYS(pfn));
		alias->end = alias->start + nr * PAGE_SIZE;
		return true;
	}

#ifdef CONFIG_X86_64
	/*
	 * If the primary call didn't touch the high mapping already
	 * and the physical address is inside the kernel map, we need
	 * to touch the high mapped kernel as well:
	 */
	if (!within(addr, (unsigned long)_text, _brk_end) && !idx--) {
		unsigned long spfn = max(pfn, highmap_start_pfn());
		unsigned long epfn = min(pfn + nr - 1, highmap_end_pfn());

		if (spfn > epfn)
			return false;

		alias->start = (spfn << PAGE_SHIFT) + __START_KERNEL_map -
			       phys_base;
		alias->end = alias->start + ((epfn - spfn + 1) << PAGE_SHIFT);
		return true;
	}
#endif

	return false;
}

int arch_cpa_hole(struct cpa_req *req, unsigned long addr)
{
	if (req->pgd)
		return 0;

	/*
	 * Ignore the NULL PTE for kernel identity mapping, as it is expected
	 * to have holes.
	 */
	if (cpa_direct_map_addr(addr))
		return 0;

#ifdef CONFIG_X86_64
	/* Faults in the highmap are OK, so do not warn: */
	if (within(addr, __START_KERNEL_map,
		   __START_KERNEL_map + KERNEL_IMAGE_SIZE))
		return -EFAULT;
#endif

	WARN(1, "CPA: called for zero pte. vaddr = %lx cpa->vaddr = %lx\n",
	     addr, req->addr);

	return -EFAULT;
}

void arch_cpa_flush(struct cpa_req *req)
{
	/*
	 * No need to flush, when we did not set any of the caching
	 * attributes:
	 */
	bool cache = pgprot2cachemode(req->set) != _PAGE_CACHE_MODE_WB;

	if (cache && !cpu_feature_enabled(X86_FEATURE_CLFLUSH)) {
		cpa_flush_all(cache);
		return;
	}

	if (req->flush_start < req->flush_end)
		flush_tlb_kernel_range(fix_addr(req->flush_start),
				       fix_addr(req->flush_end));
	if (req->alias_flush_start < req->alias_flush_end)
		flush_tlb_kernel_range(req->alias_flush_start,
				       req->alias_flush_end);

	if (cache)
		cpa_flush_cache(req->addr, req->numpages);
}

static int cpa_set_clr(unsigned long addr, int numpages, pgprot_t set,
		       pgprot_t clr, unsigned int flags)
{
	struct cpa_req req = {
		.numpages = numpages,
		.set = set,
		.clr = clr,
		.flags = flags,
	};

	if (numpages <= 0)
		return 0;

	/*
	 * People should not be passing in unaligned addresses:
	 */
	if (WARN_ON_ONCE(addr & ~PAGE_MASK))
		addr &= PAGE_MASK;
	req.addr = addr;

	return cpa_change(&req);
}

int _set_memory_uc(unsigned long addr, int numpages)
{
	/*
	 * for now UC MINUS. see comments in ioremap()
	 * If you really need strong UC use ioremap_uc(), but note
	 * that you cannot override IO areas with set_memory_*() as
	 * these helpers cannot work with IO memory.
	 */
	return cpa_set_clr(addr, numpages,
			   cachemode2pgprot(_PAGE_CACHE_MODE_UC_MINUS),
			   __pgprot(0), 0);
}

int set_memory_uc(unsigned long addr, int numpages)
{
	int ret;

	/*
	 * for now UC MINUS. see comments in ioremap()
	 */
	ret = memtype_reserve(__pa(addr), __pa(addr) + numpages * PAGE_SIZE,
			      _PAGE_CACHE_MODE_UC_MINUS, NULL);
	if (ret)
		goto out_err;

	ret = _set_memory_uc(addr, numpages);
	if (ret)
		goto out_free;

	return 0;

out_free:
	memtype_free(__pa(addr), __pa(addr) + numpages * PAGE_SIZE);
out_err:
	return ret;
}
EXPORT_SYMBOL(set_memory_uc);

int _set_memory_wc(unsigned long addr, int numpages)
{
	int ret;

	ret = cpa_set_clr(addr, numpages,
			  cachemode2pgprot(_PAGE_CACHE_MODE_UC_MINUS),
			  __pgprot(0), 0);
	if (!ret) {
		ret = cpa_set_clr(addr, numpages,
				  cachemode2pgprot(_PAGE_CACHE_MODE_WC),
				  __pgprot(_PAGE_CACHE_MASK), 0);
	}
	return ret;
}

int set_memory_wc(unsigned long addr, int numpages)
{
	int ret;

	ret = memtype_reserve(__pa(addr), __pa(addr) + numpages * PAGE_SIZE,
		_PAGE_CACHE_MODE_WC, NULL);
	if (ret)
		return ret;

	ret = _set_memory_wc(addr, numpages);
	if (ret)
		memtype_free(__pa(addr), __pa(addr) + numpages * PAGE_SIZE);

	return ret;
}
EXPORT_SYMBOL(set_memory_wc);

int _set_memory_wt(unsigned long addr, int numpages)
{
	return cpa_set_clr(addr, numpages, cachemode2pgprot(_PAGE_CACHE_MODE_WT),
			   __pgprot(0), 0);
}

int _set_memory_wb(unsigned long addr, int numpages)
{
	/* WB cache mode is hard wired to all cache attribute bits being 0 */
	return cpa_set_clr(addr, numpages, __pgprot(0),
			   __pgprot(_PAGE_CACHE_MASK), 0);
}

int set_memory_wb(unsigned long addr, int numpages)
{
	int ret;

	ret = _set_memory_wb(addr, numpages);
	if (ret)
		return ret;

	memtype_free(__pa(addr), __pa(addr) + numpages * PAGE_SIZE);
	return 0;
}
EXPORT_SYMBOL(set_memory_wb);

/* Prevent speculative access to a page by marking it not-present */
#ifdef CONFIG_X86_64
int set_mce_nospec(unsigned long pfn)
{
	unsigned long decoy_addr;
	int rc;

	/* SGX pages are not in the 1:1 map */
	if (arch_is_platform_page(pfn << PAGE_SHIFT))
		return 0;
	/*
	 * We would like to just call:
	 *      set_memory_XX((unsigned long)pfn_to_kaddr(pfn), 1);
	 * but doing that would radically increase the odds of a
	 * speculative access to the poison page because we'd have
	 * the virtual address of the kernel 1:1 mapping sitting
	 * around in registers.
	 * Instead we get tricky.  We create a non-canonical address
	 * that looks just like the one we want, but has bit 63 flipped.
	 * This relies on set_memory_XX() properly sanitizing any __pa()
	 * results with __PHYSICAL_MASK or PTE_PFN_MASK.
	 */
	decoy_addr = (pfn << PAGE_SHIFT) + (PAGE_OFFSET ^ BIT(63));

	rc = set_memory_np(decoy_addr, 1);
	if (rc)
		pr_warn("Could not invalidate pfn=0x%lx from 1:1 map\n", pfn);
	return rc;
}
EXPORT_SYMBOL_GPL(set_mce_nospec);

/* Restore full speculative operation to the pfn. */
int clear_mce_nospec(unsigned long pfn)
{
	unsigned long addr = (unsigned long) pfn_to_kaddr(pfn);

	return set_memory_p(addr, 1);
}
EXPORT_SYMBOL_GPL(clear_mce_nospec);
#endif /* CONFIG_X86_64 */
int set_memory_np_noalias(unsigned long addr, int numpages)
{
	return cpa_set_clr(addr, numpages, __pgprot(0),
			   __pgprot(_PAGE_PRESENT), CPA_NO_ALIAS);
}

int set_memory_4k(unsigned long addr, int numpages)
{
	return cpa_set_clr(addr, numpages, __pgprot(_PAGE_KERNEL_4K),
			   __pgprot(0), CPA_SPLIT);
}

int set_memory_nonglobal(unsigned long addr, int numpages)
{
	return cpa_set_clr(addr, numpages, __pgprot(0),
			   __pgprot(_PAGE_GLOBAL), 0);
}

int set_memory_global(unsigned long addr, int numpages)
{
	return cpa_set_clr(addr, numpages, __pgprot(_PAGE_GLOBAL),
			   __pgprot(0), 0);
}

/*
 * Change the direct map of runs of contiguous pages. The caller flushes the
 * TLB.
 */
static int cpa_pages_array(struct page **pages, int numpages, pgprot_t set,
			   pgprot_t clr)
{
	int i, n;
	int ret;

	for (i = 0; i < numpages; i += n) {
		unsigned long pfn = page_to_pfn(pages[i]);

		n = 1;
		if (PageHighMem(pages[i]))
			continue;

		while (i + n < numpages && !PageHighMem(pages[i + n]) &&
		       page_to_pfn(pages[i + n]) == pfn + n)
			n++;

		ret = cpa_set_clr((unsigned long)page_address(pages[i]), n,
				  set, clr, CPA_NOFLUSH);
		if (ret)
			return ret;
	}

	return 0;
}

static void cpa_flush_pages_array(struct page **pages, int numpages,
				  bool cache)
{
	int i;

	if (cache && !cpu_feature_enabled(X86_FEATURE_CLFLUSH)) {
		cpa_flush_all(cache);
		return;
	}

	flush_tlb_all();

	if (!cache)
		return;

	mb();
	for (i = 0; i < numpages; i++) {
		if (!PageHighMem(pages[i]))
			cpa_clflush_page((unsigned long)page_address(pages[i]));
	}
	mb();
}

static int _set_pages_array(struct page **pages, int numpages,
		enum page_cache_mode new_type)
{
	unsigned long start;
	unsigned long end;
	enum page_cache_mode set_type;
	int i;
	int free_idx;
	int ret;

	for (i = 0; i < numpages; i++) {
		if (PageHighMem(pages[i]))
			continue;
		start = page_to_pfn(pages[i]) << PAGE_SHIFT;
		end = start + PAGE_SIZE;
		if (memtype_reserve(start, end, new_type, NULL))
			goto err_out;
	}

	cpa_unmap_aliases();

	/* If WC, set to UC- first and then WC */
	set_type = (new_type == _PAGE_CACHE_MODE_WC) ?
				_PAGE_CACHE_MODE_UC_MINUS : new_type;

	ret = cpa_pages_array(pages, numpages, cachemode2pgprot(set_type),
			      __pgprot(0));
	if (!ret && new_type == _PAGE_CACHE_MODE_WC)
		ret = cpa_pages_array(pages, numpages,
				      cachemode2pgprot(_PAGE_CACHE_MODE_WC),
				      __pgprot(_PAGE_CACHE_MASK));
	if (ret) {
		/* WB cache mode is hard wired to all cache attribute bits being 0 */
		WARN_ON_ONCE(cpa_pages_array(pages, numpages, __pgprot(0),
					     __pgprot(_PAGE_CACHE_MASK)));
	}

	cpa_flush_pages_array(pages, numpages, true);

	if (ret)
		goto err_out;
	return 0; /* Success */
err_out:
	free_idx = i;
	for (i = 0; i < free_idx; i++) {
		if (PageHighMem(pages[i]))
			continue;
		start = page_to_pfn(pages[i]) << PAGE_SHIFT;
		end = start + PAGE_SIZE;
		memtype_free(start, end);
	}
	return -EINVAL;
}

int set_pages_array_uc(struct page **pages, int numpages)
{
	return _set_pages_array(pages, numpages, _PAGE_CACHE_MODE_UC_MINUS);
}
EXPORT_SYMBOL(set_pages_array_uc);

int set_pages_array_wc(struct page **pages, int numpages)
{
	return _set_pages_array(pages, numpages, _PAGE_CACHE_MODE_WC);
}
EXPORT_SYMBOL(set_pages_array_wc);

int set_pages_wb(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_wb(addr, numpages);
}
EXPORT_SYMBOL(set_pages_wb);

int set_pages_array_wb(struct page **pages, int numpages)
{
	int retval;
	unsigned long start;
	unsigned long end;
	int i;

	cpa_unmap_aliases();

	/* WB cache mode is hard wired to all cache attribute bits being 0 */
	retval = cpa_pages_array(pages, numpages, __pgprot(0),
				 __pgprot(_PAGE_CACHE_MASK));
	cpa_flush_pages_array(pages, numpages, false);
	if (retval)
		return retval;

	for (i = 0; i < numpages; i++) {
		if (PageHighMem(pages[i]))
			continue;
		start = page_to_pfn(pages[i]) << PAGE_SHIFT;
		end = start + PAGE_SIZE;
		memtype_free(start, end);
	}

	return 0;
}
EXPORT_SYMBOL(set_pages_array_wb);

int set_pages_ro(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_ro(addr, numpages);
}

int set_pages_rw(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_rw(addr, numpages);
}

/*
 * __set_memory_enc_pgtable() is used for the hypervisors that get
 * informed about "encryption" status via page tables.
 */
static int __set_memory_enc_pgtable(unsigned long addr, int numpages, bool enc)
{
	pgprot_t empty = __pgprot(0);
	struct cpa_req req = {
		.numpages = numpages,
		.set = enc ? pgprot_encrypted(empty) : pgprot_decrypted(empty),
		.clr = enc ? pgprot_decrypted(empty) : pgprot_encrypted(empty),
	};
	int ret;

	/* Should not be working on unaligned addresses */
	if (WARN_ONCE(addr & ~PAGE_MASK, "misaligned address: %#lx\n", addr))
		addr &= PAGE_MASK;
	req.addr = addr;

	cpa_unmap_aliases();

	/* Flush the caches as needed before changing the encryption attribute. */
	if (x86_platform.guest.enc_tlb_flush_required(enc))
		cpa_flush_range(addr, numpages,
				x86_platform.guest.enc_cache_flush_required());

	/* Notify hypervisor that we are about to set/clr encryption attribute. */
	ret = x86_platform.guest.enc_status_change_prepare(addr, numpages, enc);
	if (ret)
		goto vmm_fail;

	ret = cpa_change(&req);
	if (ret)
		return ret;

	/* Notify hypervisor that we have successfully set/clr encryption attribute. */
	ret = x86_platform.guest.enc_status_change_finish(addr, numpages, enc);
	if (ret)
		goto vmm_fail;

	return 0;

vmm_fail:
	WARN_ONCE(1, "CPA VMM failure to convert memory (addr=%p, numpages=%d) to %s: %d\n",
		  (void *)addr, numpages, enc ? "private" : "shared", ret);

	return ret;
}

/*
 * The lock serializes conversions between private and shared memory.
 *
 * It is taken for read on conversion. A write lock guarantees that no
 * concurrent conversions are in progress.
 */
static DECLARE_RWSEM(mem_enc_lock);

/*
 * Stop new private<->shared conversions.
 *
 * Taking the exclusive mem_enc_lock waits for in-flight conversions to complete.
 * The lock is not released to prevent new conversions from being started.
 */
bool set_memory_enc_stop_conversion(void)
{
	/*
	 * In a crash scenario, sleep is not allowed. Try to take the lock.
	 * Failure indicates that there is a race with the conversion.
	 */
	if (oops_in_progress)
		return down_write_trylock(&mem_enc_lock);

	down_write(&mem_enc_lock);

	return true;
}

static int __set_memory_enc_dec(unsigned long addr, int numpages, bool enc)
{
	int ret = 0;

	if (cc_platform_has(CC_ATTR_MEM_ENCRYPT)) {
		if (!down_read_trylock(&mem_enc_lock))
			return -EBUSY;

		ret = __set_memory_enc_pgtable(addr, numpages, enc);

		up_read(&mem_enc_lock);
	}

	return ret;
}

int set_memory_encrypted(unsigned long addr, int numpages)
{
	return __set_memory_enc_dec(addr, numpages, true);
}
EXPORT_SYMBOL_GPL(set_memory_encrypted);

int set_memory_decrypted(unsigned long addr, int numpages)
{
	return __set_memory_enc_dec(addr, numpages, false);
}
EXPORT_SYMBOL_GPL(set_memory_decrypted);

int set_pages_uc(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_uc(addr, numpages);
}
EXPORT_SYMBOL(set_pages_uc);

#ifdef CONFIG_DEBUG_PAGEALLOC
void __kernel_map_pages(struct page *page, int numpages, int enable)
{
	unsigned long addr;

	if (PageHighMem(page))
		return;
	if (!enable) {
		debug_check_no_locks_freed(page_address(page),
					   numpages * PAGE_SIZE);
	}

	/*
	 * Large pages for identity mappings are not used at boot time, so
	 * __kernel_map_pages() only updates existing PTEs.
	 */
	addr = (unsigned long)page_address(page);
	for (int i = 0; i < numpages; i++, addr += PAGE_SIZE) {
		pte_t *pte, old_pte, new_pte;
		unsigned int level;
		pgprot_t prot;

		pte = lookup_address(addr, &level);
		if (WARN_ON_ONCE(!pte || level != PG_LEVEL_4K))
			continue;

		old_pte = ptep_get(pte);
		if (WARN_ON_ONCE(pte_none(old_pte)))
			continue;

		prot = pte_pgprot(old_pte);
		if (enable)
			pgprot_val(prot) |= _PAGE_PRESENT | _PAGE_RW;
		else
			pgprot_val(prot) &= ~(_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY);

		prot = pgprot_clear_protnone_bits(prot);
		new_pte = pfn_pte(pte_pfn(old_pte), prot);
		if (pte_val(old_pte) != pte_val(new_pte))
			set_pte_atomic(pte, new_pte);
	}

	/*
	 * We should perform an IPI and flush all tlbs, but that can
	 * deadlock, settle for a local flush.
	 *
	 * Not doing a global TLB flush means that remote CPUs will retain
	 * stale TLB entries. In case of P->NP (on free) this means the remote
	 * CPUs will not take the faults, making the debug scheme less
	 * reliable. On the NP->P (on alloc) this means the remote CPUs can
	 * take a spurious fault. However spurious_kernel_fault() will observe
	 * *_present() and fix it up.
	 *
	 * Preemption needs to be disabled around __flush_tlb_all() due to CR3
	 * reload in __native_flush_tlb().
	 */
	preempt_disable();
	__flush_tlb_all();
	preempt_enable();

	arch_flush_lazy_mmu_mode();
}
#endif /* CONFIG_DEBUG_PAGEALLOC */
/*
 * Description of a range to populate in an EFI page table.
 */
struct cpa_data {
	pgd_t		*pgd;
	unsigned long	pfn;
	unsigned long	numpages;
	pgprot_t	mask_set;
	pgprot_t	mask_clr;
};

static bool try_to_free_pte_page(pte_t *pte)
{
	int i;

	for (i = 0; i < PTRS_PER_PTE; i++)
		if (!pte_none(pte[i]))
			return false;

	pte_free_kernel(&init_mm, pte);
	return true;
}

static bool try_to_free_pmd_page(pmd_t *pmd)
{
	int i;

	for (i = 0; i < PTRS_PER_PMD; i++)
		if (!pmd_none(pmd[i]))
			return false;

	pmd_free(&init_mm, pmd);
	return true;
}

static bool unmap_pte_range(pmd_t *pmd, unsigned long start, unsigned long end)
{
	pte_t *pte = pte_offset_kernel(pmd, start);

	while (start < end) {
		set_pte(pte, __pte(0));

		start += PAGE_SIZE;
		pte++;
	}

	if (try_to_free_pte_page((pte_t *)pmd_page_vaddr(*pmd))) {
		pmd_clear(pmd);
		return true;
	}
	return false;
}

static void __unmap_pmd_range(pud_t *pud, pmd_t *pmd,
			      unsigned long start, unsigned long end)
{
	if (unmap_pte_range(pmd, start, end))
		if (try_to_free_pmd_page(pud_pgtable(*pud)))
			pud_clear(pud);
}

static void unmap_pmd_range(pud_t *pud, unsigned long start, unsigned long end)
{
	pmd_t *pmd = pmd_offset(pud, start);

	/*
	 * Not on a 2MB page boundary?
	 */
	if (start & (PMD_SIZE - 1)) {
		unsigned long next_page = (start + PMD_SIZE) & PMD_MASK;
		unsigned long pre_end = min_t(unsigned long, end, next_page);

		__unmap_pmd_range(pud, pmd, start, pre_end);

		start = pre_end;
		pmd++;
	}

	/*
	 * Try to unmap in 2M chunks.
	 */
	while (end - start >= PMD_SIZE) {
		if (pmd_leaf(*pmd))
			pmd_clear(pmd);
		else
			__unmap_pmd_range(pud, pmd, start, start + PMD_SIZE);

		start += PMD_SIZE;
		pmd++;
	}

	/*
	 * 4K leftovers?
	 */
	if (start < end)
		return __unmap_pmd_range(pud, pmd, start, end);

	/*
	 * Try again to free the PMD page if haven't succeeded above.
	 */
	if (!pud_none(*pud))
		if (try_to_free_pmd_page(pud_pgtable(*pud)))
			pud_clear(pud);
}

static void unmap_pud_range(p4d_t *p4d, unsigned long start, unsigned long end)
{
	pud_t *pud = pud_offset(p4d, start);

	/*
	 * Not on a GB page boundary?
	 */
	if (start & (PUD_SIZE - 1)) {
		unsigned long next_page = (start + PUD_SIZE) & PUD_MASK;
		unsigned long pre_end	= min_t(unsigned long, end, next_page);

		unmap_pmd_range(pud, start, pre_end);

		start = pre_end;
		pud++;
	}

	/*
	 * Try to unmap in 1G chunks?
	 */
	while (end - start >= PUD_SIZE) {

		if (pud_leaf(*pud))
			pud_clear(pud);
		else
			unmap_pmd_range(pud, start, start + PUD_SIZE);

		start += PUD_SIZE;
		pud++;
	}

	/*
	 * 2M leftovers?
	 */
	if (start < end)
		unmap_pmd_range(pud, start, end);

	/*
	 * No need to try to free the PUD page because we'll free it in
	 * populate_pgd's error path
	 */
}

static int alloc_pte_page(pmd_t *pmd)
{
	pte_t *pte = pte_alloc_one_kernel(&init_mm);
	if (!pte)
		return -1;

	set_pmd(pmd, __pmd(__pa(pte) | _KERNPG_TABLE));
	return 0;
}

static int alloc_pmd_page(pud_t *pud)
{
	/*
	 * Pass 0 as a placeholder for the second argument, since the
	 * generic implementation of pmd_alloc_one() does not use it.
	 */
	pmd_t *pmd = pmd_alloc_one(&init_mm, 0);
	if (!pmd)
		return -1;

	set_pud(pud, __pud(__pa(pmd) | _KERNPG_TABLE));
	return 0;
}

static void populate_pte(struct cpa_data *cpa,
			 unsigned long start, unsigned long end,
			 unsigned num_pages, pmd_t *pmd, pgprot_t pgprot)
{
	pte_t *pte;

	pte = pte_offset_kernel(pmd, start);

	pgprot = pgprot_clear_protnone_bits(pgprot);

	while (num_pages-- && start < end) {
		set_pte(pte, pfn_pte(cpa->pfn, pgprot));

		start	 += PAGE_SIZE;
		cpa->pfn++;
		pte++;
	}
}

static long populate_pmd(struct cpa_data *cpa,
			 unsigned long start, unsigned long end,
			 unsigned num_pages, pud_t *pud, pgprot_t pgprot)
{
	long cur_pages = 0;
	pmd_t *pmd;
	pgprot_t pmd_pgprot;

	/*
	 * Not on a 2M boundary?
	 */
	if (start & (PMD_SIZE - 1)) {
		unsigned long pre_end = start + (num_pages << PAGE_SHIFT);
		unsigned long next_page = (start + PMD_SIZE) & PMD_MASK;

		pre_end   = min_t(unsigned long, pre_end, next_page);
		cur_pages = (pre_end - start) >> PAGE_SHIFT;
		cur_pages = min_t(unsigned int, num_pages, cur_pages);

		/*
		 * Need a PTE page?
		 */
		pmd = pmd_offset(pud, start);
		if (pmd_none(*pmd))
			if (alloc_pte_page(pmd))
				return -1;

		populate_pte(cpa, start, pre_end, cur_pages, pmd, pgprot);

		start = pre_end;
	}

	/*
	 * We mapped them all?
	 */
	if (num_pages == cur_pages)
		return cur_pages;

	pmd_pgprot = pgprot_4k_2_large(pgprot);

	while (end - start >= PMD_SIZE) {

		/*
		 * We cannot use a 1G page so allocate a PMD page if needed.
		 */
		if (pud_none(*pud))
			if (alloc_pmd_page(pud))
				return -1;

		pmd = pmd_offset(pud, start);

		set_pmd(pmd, pmd_mkhuge(pfn_pmd(cpa->pfn,
					canon_pgprot(pmd_pgprot))));

		start	  += PMD_SIZE;
		cpa->pfn  += PMD_SIZE >> PAGE_SHIFT;
		cur_pages += PMD_SIZE >> PAGE_SHIFT;
	}

	/*
	 * Map trailing 4K pages.
	 */
	if (start < end) {
		pmd = pmd_offset(pud, start);
		if (pmd_none(*pmd))
			if (alloc_pte_page(pmd))
				return -1;

		populate_pte(cpa, start, end, num_pages - cur_pages,
			     pmd, pgprot);
	}
	return num_pages;
}

static int populate_pud(struct cpa_data *cpa, unsigned long start, p4d_t *p4d,
			pgprot_t pgprot)
{
	pud_t *pud;
	unsigned long end;
	long cur_pages = 0;
	pgprot_t pud_pgprot;

	end = start + (cpa->numpages << PAGE_SHIFT);

	/*
	 * Not on a Gb page boundary? => map everything up to it with
	 * smaller pages.
	 */
	if (start & (PUD_SIZE - 1)) {
		unsigned long pre_end;
		unsigned long next_page = (start + PUD_SIZE) & PUD_MASK;

		pre_end   = min_t(unsigned long, end, next_page);
		cur_pages = (pre_end - start) >> PAGE_SHIFT;
		cur_pages = min_t(int, (int)cpa->numpages, cur_pages);

		pud = pud_offset(p4d, start);

		/*
		 * Need a PMD page?
		 */
		if (pud_none(*pud))
			if (alloc_pmd_page(pud))
				return -1;

		cur_pages = populate_pmd(cpa, start, pre_end, cur_pages,
					 pud, pgprot);
		if (cur_pages < 0)
			return cur_pages;

		start = pre_end;
	}

	/* We mapped them all? */
	if (cpa->numpages == cur_pages)
		return cur_pages;

	pud = pud_offset(p4d, start);
	pud_pgprot = pgprot_4k_2_large(pgprot);

	/*
	 * Map everything starting from the Gb boundary, possibly with 1G pages
	 */
	while (boot_cpu_has(X86_FEATURE_GBPAGES) && end - start >= PUD_SIZE) {
		set_pud(pud, pud_mkhuge(pfn_pud(cpa->pfn,
				   canon_pgprot(pud_pgprot))));

		start	  += PUD_SIZE;
		cpa->pfn  += PUD_SIZE >> PAGE_SHIFT;
		cur_pages += PUD_SIZE >> PAGE_SHIFT;
		pud++;
	}

	/* Map trailing leftover */
	if (start < end) {
		long tmp;

		pud = pud_offset(p4d, start);
		if (pud_none(*pud))
			if (alloc_pmd_page(pud))
				return -1;

		tmp = populate_pmd(cpa, start, end, cpa->numpages - cur_pages,
				   pud, pgprot);
		if (tmp < 0)
			return cur_pages;

		cur_pages += tmp;
	}
	return cur_pages;
}

/*
 * Restrictions for kernel page table do not necessarily apply when mapping in
 * an alternate PGD.
 */
static int populate_pgd(struct cpa_data *cpa, unsigned long addr)
{
	pgprot_t pgprot = __pgprot(_KERNPG_TABLE);
	pud_t *pud = NULL;	/* shut up gcc */
	p4d_t *p4d;
	pgd_t *pgd_entry;
	long ret;

	pgd_entry = cpa->pgd + pgd_index(addr);

	if (pgd_none(*pgd_entry)) {
		/*
		 * Pass 0 as a placeholder for the second argument, since the
		 * generic implementation of p4d_alloc_one() does not use it.
		 */
		p4d = p4d_alloc_one(&init_mm, 0);
		if (!p4d)
			return -1;

		set_pgd(pgd_entry, __pgd(__pa(p4d) | _KERNPG_TABLE));
	}

	/*
	 * Allocate a PUD page and hand it down for mapping.
	 */
	p4d = p4d_offset(pgd_entry, addr);
	if (p4d_none(*p4d)) {
		/*
		 * Pass 0 as a placeholder for the second argument, since the
		 * generic implementation of pud_alloc_one() does not use it.
		 */
		pud = pud_alloc_one(&init_mm, 0);
		if (!pud)
			return -1;

		set_p4d(p4d, __p4d(__pa(pud) | _KERNPG_TABLE));
	}

	pgprot_val(pgprot) &= ~pgprot_val(cpa->mask_clr);
	pgprot_val(pgprot) |=  pgprot_val(cpa->mask_set);

	ret = populate_pud(cpa, addr, p4d, pgprot);
	if (ret < 0) {
		/*
		 * Leave the PUD page in place in case some other CPU or thread
		 * already found it, but remove any useless entries we just
		 * added to it.
		 */
		unmap_pud_range(p4d, addr,
				addr + (cpa->numpages << PAGE_SHIFT));
		return ret;
	}

	cpa->numpages = ret;
	return 0;
}

/*
 * __flush_tlb_all() flushes mappings only on current CPU and hence these
 * functions shouldn't be used in an SMP environment. Presently, they are
 * used only during boot (way before smp_init()) by EFI subsystem and hence
 * are ok.
 */
static bool __init cpa_pgd_mapped(pgd_t *pgd, unsigned long addr)
{
	unsigned int level;
	pte_t *pte;

	pte = lookup_address_in_pgd(pgd + pgd_index(addr), addr, &level);
	return pte && !pte_none(*pte);
}

int __init kernel_map_pages_in_pgd(pgd_t *pgd, u64 pfn, unsigned long address,
				   unsigned numpages, unsigned long page_flags)
{
	pgprot_t clr = __pgprot(~page_flags & (_PAGE_NX|_PAGE_RW|_PAGE_DIRTY));
	pgprot_t set = __pgprot(_PAGE_PRESENT | page_flags);
	unsigned long end = address + ((unsigned long)numpages << PAGE_SHIFT);
	int retval = 0;

	WARN_ONCE(num_online_cpus() > 1, "Don't call after initializing SMP");

	if (!(__supported_pte_mask & _PAGE_NX))
		return -EINVAL;

	if (!(page_flags & _PAGE_ENC))
		clr = pgprot_encrypted(clr);

	while (address < end && !retval) {
		bool mapped = cpa_pgd_mapped(pgd, address);
		unsigned long next = address + PAGE_SIZE;

		while (next < end && cpa_pgd_mapped(pgd, next) == mapped)
			next += PAGE_SIZE;

		if (mapped) {
			struct cpa_req req = {
				.addr = address,
				.numpages = (next - address) >> PAGE_SHIFT,
				.set = set,
				.clr = clr,
				.flags = CPA_NOFLUSH | CPA_NO_ALIAS,
				.pgd = pgd,
			};

			retval = cpa_change(&req);
		} else {
			struct cpa_data cpa = {
				.pgd = pgd,
				.mask_set = set,
				.mask_clr = clr,
			};
			unsigned long addr = address;

			while (addr < next) {
				cpa.pfn = pfn + ((addr - address) >> PAGE_SHIFT);
				cpa.numpages = (next - addr) >> PAGE_SHIFT;
				if (populate_pgd(&cpa, addr) || !cpa.numpages) {
					retval = -ENOMEM;
					break;
				}
				addr += cpa.numpages << PAGE_SHIFT;
			}
		}

		pfn += (next - address) >> PAGE_SHIFT;
		address = next;
	}

	__flush_tlb_all();

	return retval;
}

int __init kernel_unmap_pages_in_pgd(pgd_t *pgd, unsigned long address,
				     unsigned long numpages)
{
	struct cpa_req req = {
		.addr = address,
		.numpages = numpages,
		.clr = __pgprot(_PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY),
		.flags = CPA_NOFLUSH | CPA_NO_ALIAS,
		.pgd = pgd,
	};
	int retval;

	WARN_ONCE(num_online_cpus() > 1, "Don't call after initializing SMP");

	retval = cpa_change(&req);
	__flush_tlb_all();

	return retval;
}
