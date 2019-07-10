/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ASS_H
#define _LINUX_ASS_H

int ass_clone_range(struct mm_struct *mm,
		    pgd_t *pgdp, pgd_t *target_pgdp,
		    unsigned long start, unsigned long end);
int ass_clone_range(struct mm_struct *mm,
		    pgd_t *pgdp, pgd_t *target_pgdp,
		    unsigned long start, unsigned long end);
int ass_free_pagetable(struct task_struct *tsk, pgd_t *ass_pgd);

#endif
