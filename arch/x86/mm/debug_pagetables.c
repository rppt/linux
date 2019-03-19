#include <linux/debugfs.h>
#include <linux/efi.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <asm/pgtable.h>

static int ptdump_show(struct seq_file *m, void *v)
{
	ptdump_walk_pgd_level_debugfs(m, NULL, PTDUMP_WALK_KERNEL);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump);

static int ptdump_curknl_show(struct seq_file *m, void *v)
{
	if (current->mm->pgd) {
		down_read(&current->mm->mmap_sem);
		ptdump_walk_pgd_level_debugfs(m, current->mm->pgd,
					      PTDUMP_WALK_KERNEL);
		up_read(&current->mm->mmap_sem);
	}
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump_curknl);

#ifdef CONFIG_PAGE_TABLE_ISOLATION
static struct dentry *pe_curusr;

static int ptdump_curusr_show(struct seq_file *m, void *v)
{
	if (current->mm->pgd) {
		down_read(&current->mm->mmap_sem);
		ptdump_walk_pgd_level_debugfs(m, current->mm->pgd,
					      PTDUMP_WALK_USER);
		up_read(&current->mm->mmap_sem);
	}
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump_curusr);
#endif

#ifdef CONFIG_INTERNAL_PTI
static struct dentry *pe_entry;

static int ptdump_entry_show(struct seq_file *m, void *v)
{
	ptdump_walk_pgd_level_debugfs(m, ((pgd_t *) &init_top_pgt),
				      PTDUMP_WALK_ENTRY);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump_entry);

static struct dentry *pe_curentry;

static int ptdump_curentry_show(struct seq_file *m, void *v)
{
	if (current->mm->pgd) {
		down_read(&current->mm->mmap_sem);
		ptdump_walk_pgd_level_debugfs(m, current->mm->pgd,
					      PTDUMP_WALK_ENTRY);
		up_read(&current->mm->mmap_sem);
	}
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump_curentry);
#endif

#if defined(CONFIG_EFI) && defined(CONFIG_X86_64)
static struct dentry *pe_efi;

static int ptdump_efi_show(struct seq_file *m, void *v)
{
	if (efi_mm.pgd)
		ptdump_walk_pgd_level_debugfs(m, efi_mm.pgd,
					      PTDUMP_WALK_KERNEL);
	return 0;
}

DEFINE_SHOW_ATTRIBUTE(ptdump_efi);
#endif

static struct dentry *dir, *pe_knl, *pe_curknl;

static int __init pt_dump_debug_init(void)
{
	dir = debugfs_create_dir("page_tables", NULL);
	if (!dir)
		return -ENOMEM;

	pe_knl = debugfs_create_file("kernel", 0400, dir, NULL,
				     &ptdump_fops);
	if (!pe_knl)
		goto err;

	pe_curknl = debugfs_create_file("current_kernel", 0400,
					dir, NULL, &ptdump_curknl_fops);
	if (!pe_curknl)
		goto err;

#ifdef CONFIG_PAGE_TABLE_ISOLATION
	pe_curusr = debugfs_create_file("current_user", 0400,
					dir, NULL, &ptdump_curusr_fops);
	if (!pe_curusr)
		goto err;
#endif

#ifdef CONFIG_INTERNAL_PTI
	pe_entry = debugfs_create_file("entry", 0400, dir, NULL,
				       &ptdump_entry_fops);
	if (!pe_entry)
		goto err;

	pe_curentry = debugfs_create_file("current_entry", 0400,
					  dir, NULL, &ptdump_curentry_fops);
	if (!pe_curentry)
		goto err;
#endif


#if defined(CONFIG_EFI) && defined(CONFIG_X86_64)
	pe_efi = debugfs_create_file("efi", 0400, dir, NULL, &ptdump_efi_fops);
	if (!pe_efi)
		goto err;
#endif

	return 0;
err:
	debugfs_remove_recursive(dir);
	return -ENOMEM;
}

static void __exit pt_dump_debug_exit(void)
{
	debugfs_remove_recursive(dir);
}

module_init(pt_dump_debug_init);
module_exit(pt_dump_debug_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arjan van de Ven <arjan@linux.intel.com>");
MODULE_DESCRIPTION("Kernel debugging helper that dumps pagetables");
