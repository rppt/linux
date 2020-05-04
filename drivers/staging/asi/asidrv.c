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

struct asidrv_test {
	struct asi		*asi;	/* ASI for testing */
	struct dpt		*dpt;	/* ASI decorated page-table */
};

static struct asidrv_test *asidrv_test;

static void asidrv_test_destroy(struct asidrv_test *test);

static struct asidrv_test *asidrv_test_create(void)
{
	struct asidrv_test *test;
	int err;

	test = kzalloc(sizeof(*test), GFP_KERNEL);
	if (!test)
		return NULL;

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

	kfree(test);
}

static const struct file_operations asidrv_fops = {
	.owner		= THIS_MODULE,
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
