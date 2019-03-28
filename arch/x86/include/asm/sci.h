// SPDX-License-Identifier: GPL-2.0
#ifndef _ASM_X86_SCI_H
#define _ASM_X86_SCI_H
#ifndef __ASSEMBLY__

#ifdef CONFIG_SYSCALL_ISOLATION
void ipti_clone_pgtable(unsigned long addr);
int ipti_pgd_alloc(struct mm_struct *mm);
void ipti_pgd_free(struct mm_struct *mm, pgd_t *pgd);
void ipti_clear_mappins(void);
bool ipti_address_is_safe(struct pt_regs *regs, unsigned long addr,
			  unsigned long hw_error_code);
#else
static inline void ipti_clone_pgtable(unsigned long addr) {}
static inline ipti_pgd_alloc(struct mm_struct *mm) { return 0; }
static inline void ipti_pgd_free(struct mm_struct *mm, pgd_t *pgd) {}
static inline void ipti_clear_mappins(void) {}
static inline bool ipti_address_is_safe(struct pt_regs *regs,unsigned long addr,
					unsigned long hw_error_code)
{
	return true;
}
#endif

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_SCI_H */
