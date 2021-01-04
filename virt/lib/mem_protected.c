#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/pagewalk.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/swap.h>
#include <asm/tlbflush.h>

static pte_t **guest_map_ptes;
static struct vm_struct *guest_map_area;

void *kvm_map_page_atomic(struct page *page)
{
	pte_t *pte;
	void *vaddr;

	/* TODO: rework to kmap_local()-like scheme */
	preempt_disable();
	pte = guest_map_ptes[smp_processor_id()];
	vaddr = guest_map_area->addr + smp_processor_id() * PAGE_SIZE;
	set_pte(pte, mk_pte(page, PAGE_KERNEL));
	return vaddr;
}
EXPORT_SYMBOL_GPL(kvm_map_page_atomic);

void kvm_unmap_page_atomic(void *vaddr)
{
	pte_t *pte = guest_map_ptes[smp_processor_id()];
	set_pte(pte, __pte(0));
	flush_tlb_one_kernel((unsigned long)vaddr);
	preempt_enable();
}
EXPORT_SYMBOL_GPL(kvm_unmap_page_atomic);

static int fill_ptes(pte_t *pte, unsigned long addr, void *data)
{
	pte_t ***p = data;

	**p = pte;
	(*p)++;

	return 0;
}

int kvm_init_protected_memory(void)
{
	guest_map_ptes = kmalloc_array(num_possible_cpus(),
				       sizeof(pte_t *), GFP_KERNEL);
	if (!guest_map_ptes)
		return -ENOMEM;

	guest_map_area = get_vm_area(PAGE_SIZE * num_possible_cpus(),
				     VM_IOREMAP);
	if (!guest_map_ptes) {
		kfree(guest_map_ptes);
		return -ENOMEM;
	}

	if (apply_to_page_range(&init_mm, (unsigned long)guest_map_area->addr,
				PAGE_SIZE * num_possible_cpus(), fill_ptes,
				&guest_map_ptes)) {
		free_vm_area(guest_map_area);
		kfree(guest_map_ptes);
		return -ENOMEM;
	}
	/* Undo guest_map_ptes shifting in the fill_ptes */
	guest_map_ptes -= num_possible_cpus();

	return 0;
}
EXPORT_SYMBOL_GPL(kvm_init_protected_memory);

void kvm_exit_protected_memory(void)
{
	if (guest_map_area)
		free_vm_area(guest_map_area);
	if (guest_map_ptes)
		kfree(guest_map_ptes);
}
EXPORT_SYMBOL_GPL(kvm_exit_protected_memory);

