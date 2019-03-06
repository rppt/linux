// SPDX-License-Identifier: GPL-2.0
#ifndef _ASM_X86_PTI_H
#define _ASM_X86_PTI_H
#ifndef __ASSEMBLY__

#ifdef CONFIG_PAGE_TABLE_ISOLATION
extern void pti_init(void);
extern void pti_check_boottime_disable(void);
extern void pti_finalize(void);
#else
static inline void pti_check_boottime_disable(void) { }
#endif

void pti_clone_pgtable_pmd(unsigned long start, unsigned long end,
			   bool entry);
void pti_clone_pgtable_pte(unsigned long start, unsigned long end,
			   bool entry);

#ifdef CONFIG_INTERNAL_PTI
void ipti_clone_pgtable(unsigned long addr);
int ipti_pgd_alloc(struct mm_struct *mm);
void ipti_pgd_free(struct mm_struct *mm, pgd_t *pgd);
int ipti_add_mapping(unsigned long address);
void ipti_clear_mappins(void);
bool ipti_address_is_safe(struct pt_regs *regs, unsigned long addr,
			  unsigned long hw_error_code);
#else
static inline void ipti_clone_pgtable(unsigned long addr) {}
static inline ipti_pgd_alloc(struct mm_struct *mm) { return 0; }
static inline void ipti_pgd_free(struct mm_struct *mm, pgd_t *pgd) {}
static inline int ipti_add_mapping(unsigned long address) { return 0; }
static inline void ipti_clear_mappins(void) {}
static inline bool ipti_address_is_safe(struct pt_regs *regs,unsigned long addr,
					unsigned long hw_error_code)
{
	return true;
}
#endif

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_PTI_H */
