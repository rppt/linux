/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CET_H
#define _ASM_X86_CET_H

#ifndef __ASSEMBLY__
#include <linux/types.h>

struct task_struct;

struct thread_shstk {
	u64	base;
	u64	size;
};

#ifdef CONFIG_X86_SHADOW_STACK
long cet_prctl(struct task_struct *task, int option,
		      unsigned long features);
int shstk_setup(void);
void shstk_free(struct task_struct *p);
int shstk_disable(void);
void reset_thread_shstk(void);
#else
static inline long cet_prctl(struct task_struct *task, int option,
		      unsigned long features) { return -EINVAL; }
static inline int shstk_setup(void) { return -EOPNOTSUPP; }
static inline void shstk_free(struct task_struct *p) {}
static inline int shstk_disable(void) { return -EOPNOTSUPP; }
static inline void reset_thread_shstk(void) {}
#endif /* CONFIG_X86_SHADOW_STACK */

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_CET_H */
