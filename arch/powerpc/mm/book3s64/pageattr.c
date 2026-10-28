// SPDX-License-Identifier: GPL-2.0
/*
 * Changing kernel page permissions on Book3S 64.
 *
 * Radix does not allow translations of different sizes for the same
 * address, so large leaves are never split. Hash only has vmalloc and IO
 * in the Linux page tables, mapped with base pages.
 */
#include <linux/mm.h>
#include <linux/pageattr.h>
#include <linux/vmalloc.h>
#include <asm/tlbflush.h>

struct cpa_prot_op arch_cpa_prot_ops[CPA_PROT_NR] __ro_after_init = {
	/* Don't clear DIRTY bit */
	[CPA_PROT_RO] = { .clr = __pgprot(_PAGE_WRITE) },
	[CPA_PROT_RW] = { .set = __pgprot(_PAGE_WRITE | _PAGE_DIRTY) },
	[CPA_PROT_X]  = { .set = __pgprot(_PAGE_EXEC) },
	[CPA_PROT_NX] = { .clr = __pgprot(_PAGE_EXEC) },
	[CPA_PROT_NP] = { .clr = __pgprot(_PAGE_PRESENT) },
	[CPA_PROT_P]  = { .set = __pgprot(_PAGE_PRESENT) },
};

/* Leaves have the same format at all levels */
bool arch_cpa_read_leaf(struct cpa_leaf *leaf)
{
	unsigned long val = pte_val(ptep_get((pte_t *)leaf->entry));

	if (leaf->level != PGTABLE_LEVEL_PTE && !(val & _PAGE_PTE))
		return false;

	leaf->pfn = (val & PTE_RPN_MASK) >> PTE_RPN_SHIFT;
	leaf->prot = __pgprot(val & ~PTE_RPN_MASK);

	return true;
}

/* Only change the bits of the request, hash may update the others */
void arch_cpa_write_leaf(struct cpa_req *req, struct cpa_leaf *leaf,
			 pgprot_t prot)
{
	unsigned long old = pgprot_val(leaf->prot);
	unsigned long new = pgprot_val(prot);

	pte_update(&init_mm, leaf->start, leaf->entry, old & ~new, new & ~old,
		   leaf->level != PGTABLE_LEVEL_PTE);
}

int arch_cpa_check(struct cpa_req *req)
{
	void *addr = (void *)req->addr;
	int region;

	if (WARN_ON_ONCE(is_vmalloc_or_module_addr(addr) &&
			 is_vm_area_hugepages(addr)))
		return -EINVAL;

	if (radix_enabled())
		return 0;

	/* On hash, the linear mapping is not in the Linux page table */
	region = get_region_id(req->addr);
	if (WARN_ON_ONCE(region != VMALLOC_REGION_ID && region != IO_REGION_ID))
		return -EINVAL;

	return 0;
}

void arch_cpa_flush(struct cpa_req *req)
{
	/* hash invalidates the HPTEs in pte_update() */
	if (!radix_enabled())
		return;

	/* See ptesync comment in radix__set_pte_at() */
	asm volatile("ptesync" : : : "memory");

	if (req->flags & CPA_NOFLUSH)
		return;

	cpa_flush_ranges(req);
}
