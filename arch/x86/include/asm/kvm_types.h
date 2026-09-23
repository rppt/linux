/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KVM_TYPES_H
#define _ASM_X86_KVM_TYPES_H

#if IS_MODULE(CONFIG_KVM_AMD) && IS_MODULE(CONFIG_KVM_INTEL)
#define KVM_SUB_MODULES kvm-amd,kvm-intel
#elif IS_MODULE(CONFIG_KVM_AMD)
#define KVM_SUB_MODULES kvm-amd
#elif IS_MODULE(CONFIG_KVM_INTEL)
#define KVM_SUB_MODULES kvm-intel
#else
#undef KVM_SUB_MODULES
/*
 * Don't export symbols for KVM without vendor modules, as kvm.ko is built iff
 * at least one vendor module is enabled.
 */
#define EXPORT_SYMBOL_FOR_KVM(symbol)
#endif

#ifndef __ASSEMBLER__
/* Levels of the page tables KVM manages for a guest */
enum kvm_pt_level {
	KVM_PT_LEVEL_NONE,
	KVM_PT_LEVEL_PTE,
	KVM_PT_LEVEL_PMD,
	KVM_PT_LEVEL_PUD,
	KVM_PT_LEVEL_P4D,
	KVM_PT_LEVEL_PGD,
	KVM_PT_LEVEL_NUM
};
#endif /* !__ASSEMBLER__ */

#define KVM_ARCH_NR_OBJS_PER_MEMORY_CACHE 40

#endif /* _ASM_X86_KVM_TYPES_H */
