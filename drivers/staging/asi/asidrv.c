// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020, Oracle and/or its affiliates.
 */

#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <asm/asi.h>
#include <asm/dpt.h>
#include <asm/tlbflush.h>

#include "asidrv.h"

#define ASIDRV_TEST_BUFFER_SIZE	PAGE_SIZE

/* Number of read for mem/memmap test sequence */
#define ASIDRV_MEM_READ_COUNT		1000

enum asidrv_state {
	ASIDRV_STATE_NONE,
	ASIDRV_STATE_INTR_WAITING,
	ASIDRV_STATE_INTR_RECEIVED,
};

struct asidrv_test {
	struct asi		*asi;	/* ASI for testing */
	struct dpt		*dpt;	/* ASI decorated page-table */
	char			*buffer; /* buffer for testing */
};

struct asidrv_sequence {
	const char *name;
	enum asidrv_run_error (*setup)(struct asidrv_test *t);
	enum asidrv_run_error (*run)(struct asidrv_test *t);
	void (*cleanup)(struct asidrv_test *t);
};

static struct asidrv_test *asidrv_test;

static void asidrv_test_destroy(struct asidrv_test *test);
static void asidrv_run_fini(struct asidrv_test *test);
static void asidrv_run_cleanup(struct asidrv_test *test,
			       struct asidrv_sequence *sequence);

static struct asidrv_test *asidrv_test_create(void)
{
	struct asidrv_test *test;
	int err;

	test = kzalloc(sizeof(*test), GFP_KERNEL);
	if (!test)
		return NULL;

	test->buffer = kzalloc(ASIDRV_TEST_BUFFER_SIZE, GFP_KERNEL);
	if (!test->buffer)
		goto error;

	/*
	 * Create and fill a decorator page-table to be used with the ASI.
	 */
	test->dpt = dpt_create(ASI_PGTABLE_MASK);
	if (!test->dpt)
		goto error;

	err = asi_init_dpt(test->dpt);
	if (err)
		goto error;

	err = DPT_MAP_THIS_MODULE(test->dpt);
	if (err)
		goto error;

	/* map the asidrv_test as we will access it during the test */
	err = dpt_map(test->dpt, test, sizeof(*test));
	if (err)
		goto error;

	test->asi = asi_create_test();
	if (!test->asi)
		goto error;

	/*
	 * By default, the ASI structure is not mapped into the ASI. We
	 * map it so that we can access it and verify the consistency
	 * of some values (for example the CR3 value).
	 */
	err = dpt_map(test->dpt, test->asi, sizeof(*test->asi));
	if (err)
		goto error;

	asi_set_pagetable(test->asi, test->dpt->pagetable);

	return test;

error:
	pr_debug("Failed to create ASI Test\n");
	asidrv_test_destroy(test);
	return NULL;
}

static void asidrv_test_destroy(struct asidrv_test *test)
{
	if (!test)
		return;

	if (test->dpt)
		dpt_destroy(test->dpt);

	if (test->asi)
		asi_destroy(test->asi);

	kfree(test->buffer);
	kfree(test);
}

static int asidrv_asi_is_active(struct asi *asi)
{
	struct asi *current_asi;
	unsigned long cr3;
	bool is_active;
	int idepth;

	if (!asi)
		return false;

	current_asi = this_cpu_read(cpu_asi_session.asi);
	if (current_asi == asi) {
		idepth = this_cpu_read(cpu_asi_session.idepth);
		is_active = (idepth == 0);
	} else {
		is_active = false;
		if (current_asi) {
			/* weird... another ASI is active! */
			pr_debug("ASI %px is active (testing ASI = %px)\n",
				 current_asi, asi);
		}
	}

	/*
	 * If the ASI is active check that the CR3 value is consistent with
	 * this ASI being active. Otherwise, check that CR3 value doesn't
	 * reference an ASI.
	 */
	cr3 = __native_read_cr3();
	if (is_active) {
		if ((cr3 ^ asi->base_cr3) >> ASI_PCID_PREFIX_SHIFT == 0)
			return true;

		pr_warn("ASI %px: active ASI has inconsistent CR3 value (cr3=%lx, ASI base=%lx)\n",
			asi, cr3, asi->base_cr3);

	} else if (cr3 & ASI_PCID_PREFIX_MASK) {
		pr_warn("ASI %px: inactive ASI has inconsistent CR3 value (cr3=%lx, ASI base=%lx)\n",
			asi, cr3, asi->base_cr3);
	}

	return false;
}

/*
 * Memory Buffer Access Test Sequences
 */

#define OPTNONE __attribute__((optimize(0)))

static enum asidrv_run_error OPTNONE asidrv_mem_run(struct asidrv_test *test)
{
	char c;
	int i, index;

	/*
	 * Do random reads in the test buffer, and return if the ASI
	 * becomes inactive.
	 */
	for (i = 0; i < ASIDRV_MEM_READ_COUNT; i++) {
		index = get_cycles() % ASIDRV_TEST_BUFFER_SIZE;
		c = test->buffer[index];
		if (!asidrv_asi_is_active(test->asi)) {
			pr_warn("ASI inactive after reading byte %d at %d\n",
				i + 1, index);
			break;
		}
	}

	return ASIDRV_RUN_ERR_NONE;
}

static enum asidrv_run_error asidrv_memmap_setup(struct asidrv_test *test)
{
	int err;

	pr_debug("mapping test buffer %px\n", test->buffer);
	err = dpt_map(test->dpt, test->buffer, ASIDRV_TEST_BUFFER_SIZE);
	if (err)
		return ASIDRV_RUN_ERR_MAP_BUFFER;

	return ASIDRV_RUN_ERR_NONE;
}

static void asidrv_memmap_cleanup(struct asidrv_test *test)
{
	dpt_unmap(test->dpt, test->buffer);
}

/*
 * Printk Test Sequence
 */
static enum asidrv_run_error asidrv_printk_run(struct asidrv_test *test)
{
	pr_notice("asidrv printk test...\n");
	return ASIDRV_RUN_ERR_NONE;
}

struct asidrv_sequence asidrv_sequences[] = {
	[ASIDRV_SEQ_NOP] = {
		"nop",
		NULL, NULL, NULL,
	},
	[ASIDRV_SEQ_PRINTK] = {
		"printk",
		NULL, asidrv_printk_run, NULL,
	},
	[ASIDRV_SEQ_MEM] = {
		"mem",
		NULL, asidrv_mem_run, NULL,
	},
	[ASIDRV_SEQ_MEMMAP] = {
		"memmap",
		asidrv_memmap_setup, asidrv_mem_run, asidrv_memmap_cleanup,
	},
};

static enum asidrv_run_error asidrv_run_init(struct asidrv_test *test)
{
	int err;

	/*
	 * Map the current stack, we need it to enter ASI.
	 */
	err = dpt_map(test->dpt, current->stack,
		      PAGE_SIZE << THREAD_SIZE_ORDER);
	if (err) {
		asidrv_run_fini(test);
		return ASIDRV_RUN_ERR_MAP_STACK;
	}

	/*
	 * Map the current task, schedule() needs it.
	 */
	err = dpt_map(test->dpt, current, sizeof(struct task_struct));
	if (err)
		return ASIDRV_RUN_ERR_MAP_TASK;

	/*
	 * The ASI page-table has been updated so bump the generation
	 * number to have the ASI TLB flushed.
	 */
	atomic64_inc(&test->asi->pgtable_gen);

	return ASIDRV_RUN_ERR_NONE;
}

static void asidrv_run_fini(struct asidrv_test *test)
{
	dpt_unmap(test->dpt, current);
	dpt_unmap(test->dpt, current->stack);
}

static enum asidrv_run_error asidrv_run_setup(struct asidrv_test *test,
					      struct asidrv_sequence *sequence)
{
	int run_err = ASIDRV_RUN_ERR_NONE;

	if (sequence->setup) {
		run_err = sequence->setup(test);
		if (run_err)
			goto failed;
	}

	return ASIDRV_RUN_ERR_NONE;

failed:
	return run_err;
}

static void asidrv_run_cleanup(struct asidrv_test *test,
			       struct asidrv_sequence *sequence)
{
	if (sequence->cleanup)
		sequence->cleanup(test);
}

/*
 * Run the specified sequence with ASI. Report result back.
 */
static enum asidrv_run_error asidrv_run(struct asidrv_test *test,
					enum asidrv_seqnum seqnum,
					bool *asi_active)
{
	struct asidrv_sequence *sequence = &asidrv_sequences[seqnum];
	int run_err = ASIDRV_RUN_ERR_NONE;
	int err = 0;

	if (seqnum >= ARRAY_SIZE(asidrv_sequences)) {
		pr_debug("Undefined sequence %d\n", seqnum);
		return ASIDRV_RUN_ERR_SEQUENCE;
	}

	pr_debug("ASI running sequence %s\n", sequence->name);

	run_err = asidrv_run_setup(test, sequence);
	if (run_err)
		return run_err;

	err = asi_enter(test->asi);
	if (err) {
		run_err = ASIDRV_RUN_ERR_ENTER;
		goto failed_noexit;
	}

	if (!asidrv_asi_is_active(test->asi)) {
		run_err = ASIDRV_RUN_ERR_ACTIVE;
		goto failed;
	}

	if (sequence->run) {
		run_err = sequence->run(test);
		if (run_err != ASIDRV_RUN_ERR_NONE)
			goto failed;
	}

	*asi_active = asidrv_asi_is_active(test->asi);

failed:
	asi_exit(test->asi);

failed_noexit:
	asidrv_run_cleanup(test, sequence);

	return run_err;
}

static int asidrv_ioctl_run_sequence(struct asidrv_test *test,
				     unsigned long arg)
{
	struct asidrv_run_param __user *urparam;
	struct asidrv_run_param rparam;
	enum asidrv_run_error run_err;
	enum asidrv_seqnum seqnum;
	bool asi_active = false;

	urparam = (struct asidrv_run_param *)arg;
	if (copy_from_user(&rparam, urparam, sizeof(rparam)))
		return -EFAULT;

	seqnum = rparam.sequence;

	pr_debug("ASI sequence %d\n", seqnum);

	run_err = asidrv_run_init(test);
	if (run_err) {
		pr_debug("ASI run init error %d\n", run_err);
		goto failed_nofini;
	}

	run_err = asidrv_run(test, seqnum, &asi_active);
	if (run_err) {
		pr_debug("ASI run error %d\n", run_err);
	} else {
		pr_debug("ASI run okay, ASI is %s\n",
			 asi_active ? "active" : "inactive");
	}

	asidrv_run_fini(test);

failed_nofini:
	rparam.run_error = run_err;
	rparam.asi_active = asi_active;

	if (copy_to_user(urparam, &rparam, sizeof(rparam)))
		return -EFAULT;

	return 0;
}

static long asidrv_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct asidrv_test *test = asidrv_test;

	switch (cmd) {

	/* Test ioctls */

	case ASIDRV_IOCTL_RUN_SEQUENCE:
		return asidrv_ioctl_run_sequence(test, arg);

	default:
		return -ENOTTY;
	};
}

static const struct file_operations asidrv_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= asidrv_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
};

static struct miscdevice asidrv_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = KBUILD_MODNAME,
	.fops = &asidrv_fops,
};

static int __init asidrv_init(void)
{
	int err;

	asidrv_test = asidrv_test_create();
	if (!asidrv_test)
		return -ENOMEM;

	err = misc_register(&asidrv_miscdev);
	if (err) {
		asidrv_test_destroy(asidrv_test);
		asidrv_test = NULL;
	}

	return err;
}

static void __exit asidrv_exit(void)
{
	asidrv_test_destroy(asidrv_test);
	asidrv_test = NULL;
	misc_deregister(&asidrv_miscdev);
}

module_init(asidrv_init);
module_exit(asidrv_exit);

MODULE_AUTHOR("Alexandre Chartre <alexandre.chartre@oracle.com>");
MODULE_DESCRIPTION("Privileged interface to ASI");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL v2");
