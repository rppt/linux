// SPDX-License-Identifier: GPL-2.0
#include <linux/asi.h>
#include <linux/gfp.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched/mm.h>

#define ASIDRV_TEST_GFP_UNMAP		0x10
#define ASIDRV_TEST_GFP_EXCLUSIVE	0x20
#define ASIDRV_TEST_KMALLOC		0x30

static bool vaddr_present(pgd_t *base, unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset_pgd(base, addr);
	if (!pgd_present(*pgd))
		return false;

#define pt_present(pt, ptup, addr) {	\
	pt = pt##_offset(ptup, addr);	\
	if (!pt##_present(*(pt)))	\
		return false;		\
	if (pt##_large(*(pt)))		\
		return true;		\
	}

	pt_present(p4d, pgd, addr);
	pt_present(pud, p4d, addr);
	pt_present(pmd, pud, addr);

#undef pt_present

	pte = pte_offset_kernel(pmd, addr);
	return pte_present(*pte);
}

static bool page_present(pgd_t *pgd, struct page *page)
{
	return vaddr_present(pgd, (unsigned long)page_address(page));
}

static int test_gfp_unmap(void)
{
	struct page *page = alloc_pages(GFP_KERNEL |__GFP_UNMAP, 0);

	if (!page)
		return -ENOMEM;

	if (page_present(init_mm.pgd, page))
		return -EINVAL;

	return 0;
}

static int test_gfp_exclusive(void)
{
	struct page *page = alloc_pages(GFP_KERNEL |__GFP_EXCLUSIVE, 0);
	unsigned long addr = (unsigned long)page_address(page);

	if (!page)
		return -ENOMEM;

	if (page_present(init_mm.pgd, page))
		return -EINVAL;

	if (!page_present(current->mm->pgd, page))
		return -EINVAL;

	if (addr < EXCLUSIVE_START || addr > (EXCLUSIVE_START + EXCLUSIVE_SIZE))
		return -EINVAL;

	return 0;
}

static int test_kmalloc(void)
{
	struct mm_struct *mm, *test_obj;
	struct asi_ctx asi;
	unsigned long addr;
	int err;

	mm = mm_alloc();
	if (!mm)
		return -ENOMEM;

	asi.mm = mm;
	asi.pgd = mm->pgd;

	/* fake a restricted context for the current mm */
	current->mm->asi_ctx = &asi;
	this_cpu_write(asi_ctx_pcpu, &asi);

	err = asi_init_slab(&asi);
	if (err)
		goto err_clean_fake_asi;

	test_obj = kmalloc(sizeof(*test_obj), GFP_KERNEL | __GFP_EXCLUSIVE);
	if (!test_obj) {
		err = -ENOMEM;
		goto err_clean_fake_asi;
	}

	addr = (unsigned long)test_obj;
	if (vaddr_present(init_mm.pgd, addr)) {
		err = -EINVAL;
		goto err_free_test_obj;
	}

	if (!vaddr_present(mm->pgd, addr)) {
		err = -E2BIG;
		goto err_free_test_obj;
	}

	err = 0;

err_free_test_obj:
	kfree(test_obj);
err_clean_fake_asi:
	current->mm->asi_ctx = NULL;
	this_cpu_write(asi_ctx_pcpu, NULL);
	mmput(mm);
	return err;
}

static long asidrv_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret = -EINVAL;

	switch (cmd) {
	case ASIDRV_TEST_GFP_UNMAP:
		ret = test_gfp_unmap();
		break;
	case ASIDRV_TEST_GFP_EXCLUSIVE:
		ret = test_gfp_exclusive();
		break;
	case ASIDRV_TEST_KMALLOC:
		ret = test_kmalloc();
		break;
	default:
		break;
	}

	return ret;
}

static const struct file_operations asidrv_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= asidrv_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
};

static struct miscdevice asidrv_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "asi",
	.fops = &asidrv_fops,
};

static int __init asidrv_init(void)
{
	return misc_register(&asidrv_miscdev);
}
fs_initcall(asidrv_init);
