// SPDX-License-Identifier: GPL-2.0
/*
 * Changing kernel page permissions on Book3S 64.
 *
 * Radix forbids translations of different sizes for the same address, so
 * large leaves can be neither split nor collapsed while they are in use.
 *
 * Hash only has vmalloc and IO in the Linux page tables, both mapped with
 * base pages, and pte_update() invalidates the HPTEs.
 */
#include <linux/pageattr.h>

void arch_cpa_prot(enum cpa_prot_op op, pgprot_t *set, pgprot_t *clr)
{
	unsigned long s = 0, c = 0;

	switch (op) {
	case CPA_PROT_RO:
		/* keep the C bit, the hardware would set it otherwise */
		c = _PAGE_WRITE;
		s = _PAGE_READ;
		break;
	case CPA_PROT_RW:
		s = _PAGE_RW | _PAGE_DIRTY;
		break;
	case CPA_PROT_X:
		s = _PAGE_EXEC;
		break;
	case CPA_PROT_NX:
		c = _PAGE_EXEC;
		break;
	case CPA_PROT_NP:
	case CPA_PROT_INVALID:
		c = _PAGE_PRESENT;
		break;
	case CPA_PROT_P:
		s = _PAGE_PRESENT;
		break;
	case CPA_PROT_DEFAULT:
		s = _PAGE_PRESENT | _PAGE_RW | _PAGE_DIRTY | _PAGE_ACCESSED;
		c = _PAGE_EXEC;
		break;
	}

	*set = __pgprot(s);
	*clr = __pgprot(c);
}

/* Leaves have the same format at all levels */
void arch_cpa_read_leaf(struct cpa_leaf *leaf)
{
	unsigned long val = pte_val(ptep_get(leaf->entry));

	leaf->pfn = (val & PTE_RPN_MASK) >> PTE_RPN_SHIFT;
	leaf->prot = __pgprot(val & ~PTE_RPN_MASK);
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

int arch_cpa_check_range(struct cpa_req *req)
{
	int region;

	if (radix_enabled())
		return 0;

	region = get_region_id(req->addr);
	if (WARN_ON_ONCE(region != VMALLOC_REGION_ID && region != IO_REGION_ID))
		return -EINVAL;

	return 0;
}

/* Spurious faults on kernel memory are not tolerated, see radix__set_pte_at() */
void arch_cpa_leave(struct cpa_req *req)
{
	if (radix_enabled())
		asm volatile("ptesync" : : : "memory");
}
