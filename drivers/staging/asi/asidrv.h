/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */

#ifndef __ASIDRV_H__
#define __ASIDRV_H__

#include <linux/types.h>

enum asidrv_seqnum {
	ASIDRV_SEQ_NOP,		/* empty sequence */
	ASIDRV_SEQ_PRINTK,	/* printk sequence */
	ASIDRV_SEQ_MEM,		/* access unmapped memory */
	ASIDRV_SEQ_MEMMAP,	/* access mapped memory */
	ASIDRV_SEQ_INTERRUPT,	/* interrupt sequence */
	ASIDRV_SEQ_NMI,		/* NMI interrupt sequence */
	ASIDRV_SEQ_INTRNMI,	/* NMI in interrupt sequence */
	ASIDRV_SEQ_SCHED,	/* schedule() sequence */
};

enum asidrv_run_error {
	ASIDRV_RUN_ERR_NONE,	/* no error */
	ASIDRV_RUN_ERR_SEQUENCE, /* unknown sequence */
	ASIDRV_RUN_ERR_MAP_STACK, /* failed to map current stack */
	ASIDRV_RUN_ERR_MAP_TASK, /* failed to map current task */
	ASIDRV_RUN_ERR_ENTER,	/* failed to enter ASI */
	ASIDRV_RUN_ERR_ACTIVE,	/* ASI is not active after entering ASI */
	ASIDRV_RUN_ERR_MAP_BUFFER, /* failed to map buffer */
	ASIDRV_RUN_ERR_NCPUS,	/* not enough active cpus */
	ASIDRV_RUN_ERR_INTR,	/* no interrupt received */
	ASIDRV_RUN_ERR_INTR_ASI_ACTIVE, /* ASI active in interrupt handler */
	ASIDRV_RUN_ERR_TIMEOUT,
	ASIDRV_RUN_ERR_NMI,	/* no NMI received */
	ASIDRV_RUN_ERR_NMI_REG,	/* failed to register NMI handler */
	ASIDRV_RUN_ERR_NMI_ASI_ACTIVE, /* ASI active in NMI handler */
	ASIDRV_RUN_ERR_KTHREAD,	/* failed to create kernel thread */
};

#define ASIDRV_IOCTL_RUN_SEQUENCE	_IOWR('a', 1, struct asidrv_run_param)

struct asidrv_run_param {
	__u32 sequence;		/* sequence to run */
	__u32 run_error;	/* result error after run */
	__u32 asi_active;	/* ASI is active after run? */
};
#endif
