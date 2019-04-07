// SPDX-License-Identifier: GPL-2.0
#ifndef _ASM_X86_SCI_H
#define _ASM_X86_SCI_H
#ifndef __ASSEMBLY__

#ifdef CONFIG_SYSCALL_ISOLATION

void sci_check_boottime_disable(void);

int sci_pgd_alloc(struct mm_struct *mm);
void sci_pgd_free(struct mm_struct *mm, pgd_t *pgd);

bool sci_verify_and_map(struct pt_regs *regs, unsigned long addr,
			unsigned long hw_error_code);
void sci_clear_data(void);

#else

static inline void sci_check_boottime_disable(void) {}

static inline int sci_pgd_alloc(struct mm_struct *mm) { return 0; }
static inline void sci_pgd_free(struct mm_struct *mm, pgd_t *pgd) {}

static inline bool sci_verify_and_map(struct pt_regs *regs,unsigned long addr,
				      unsigned long hw_error_code)
{
	return true;
}
static inline void sci_clear_data(void) {}

#endif

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_SCI_H */
