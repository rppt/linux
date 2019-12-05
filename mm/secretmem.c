// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/memfd.h>
#include <linux/pseudo_fs.h>
#include <linux/set_memory.h>
#include <uapi/linux/memfd.h>

#include <asm/tlb.h>

#define SECRETMEM_EXCLUSIVE	0x1
#define SECRETMEM_UNCACHED	0x2

static struct vfsmount *secretmem_mnt;

struct secretmem_state {
	unsigned int mode;
};

void smem_dump_page(struct page *page, const char *msg)
{
	unsigned long addr = (unsigned long)page_address(page);
	unsigned int level;
	pte_t *pte;

	pte = lookup_address(addr, &level);
	pr_info("%s: addr: %lx, pte: %lx, level: %d\n", msg, addr, pte_val(*pte), level);
	dump_page(page, msg);
}

static vm_fault_t secretmem_fault(struct vm_fault *vmf)
{
	struct secretmem_state *state = vmf->vma->vm_file->private_data;
	struct address_space *mapping = vmf->vma->vm_file->f_mapping;
	pgoff_t offset = vmf->pgoff;
	unsigned long addr;
	struct page *page;
	int err;

	page = find_or_create_page(mapping, offset, mapping_gfp_mask(mapping));
	if (!page)
		return vmf_error(-ENOMEM);
	addr = (unsigned long)page_address(page);

	smem_dump_page(page, "S_fault start");

	if (state->mode == SECRETMEM_EXCLUSIVE)
		err = set_direct_map_invalid_noflush(page);
	else if (state->mode == SECRETMEM_UNCACHED)
		err = set_pages_array_uc(&page, 1);
	else
		BUG();

	if (err) {
		delete_from_page_cache(page);
		return vmf_error(err);
	}

	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);

	smem_dump_page(page, "S_fault end");

	vmf->page = page;
	return  VM_FAULT_LOCKED;
}

static void secretmem_close(struct vm_area_struct *vma)
{
	struct secretmem_state *state = vma->vm_file->private_data;
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct page *page;
	pgoff_t index;

	pr_info("%s: \n", __func__ );

	xa_for_each(&mapping->i_pages, index, page) {
		unsigned long addr;

		addr = (unsigned long)page_address(page);

		smem_dump_page(page, "S_close start");

		get_page(page);
		lock_page(page);

		if (state->mode == SECRETMEM_EXCLUSIVE)
			set_direct_map_default_noflush(page);
		else if (state->mode == SECRETMEM_UNCACHED)
			set_pages_array_wb(&page, 1);
		else
			BUG();

		delete_from_page_cache(page);

		unlock_page(page);
		put_page(page);

		smem_dump_page(page, "S_close end");
	}
}

static const struct vm_operations_struct secretmem_vm_ops = {
	.fault = secretmem_fault,
	.close = secretmem_close,
};

static int secretmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct secretmem_state *state = file->private_data;
	unsigned long mode = state->mode;

	if (!mode)
		return -EINVAL;

	switch (mode) {
	case SECRETMEM_UNCACHED:
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		/* fallthrough */
	case SECRETMEM_EXCLUSIVE:
		vma->vm_ops = &secretmem_vm_ops;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static long secretmem_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	struct secretmem_state *state = file->private_data;
	unsigned long mode = state->mode;

	if (mode)
		return -EINVAL;

	switch (cmd) {
	case MFD_SECRET_EXCLUSIVE:
		mode = SECRETMEM_EXCLUSIVE;
		break;
	case MFD_SECRET_UNCACHED:
		mode = SECRETMEM_UNCACHED;
		break;
	default:
		return -EINVAL;
	}

	state->mode = mode;

	return 0;
}

static int secretmem_release(struct inode *inode, struct file *file)
{
	struct secretmem_state *state = file->private_data;

	kfree(state);

	return 0;
}

/* static const struct address_space_operations secretmem_aops = { */
/* }; */

const struct file_operations secretmem_fops = {
	.release	= secretmem_release,
	.mmap		= secretmem_mmap,
	.unlocked_ioctl = secretmem_ioctl,
	.compat_ioctl	= secretmem_ioctl,
};

struct file *secretmem_file_create(const char *name, unsigned int flags)
{
	struct inode *inode = alloc_anon_inode(secretmem_mnt->mnt_sb);
	struct file *file = ERR_PTR(-ENOMEM);
	struct secretmem_state *state;

	if (IS_ERR(inode))
		return ERR_CAST(inode);

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		goto err_free_inode;

	file = alloc_file_pseudo(inode, secretmem_mnt, "secretmem",
				 O_RDWR, &secretmem_fops);
	if (IS_ERR(file))
		goto err_free_state;

	mapping_set_unevictable(inode->i_mapping);

	file->f_flags |= O_LARGEFILE;
	file->private_data = state;

	return file;

err_free_state:
	kfree(state);
err_free_inode:
	iput(inode);
	return file;
}

#define SECRETMEM_MAGIC 0x44

static int secretmem_init_fs_context(struct fs_context *fc)
{
	return init_pseudo(fc, SECRETMEM_MAGIC) ? 0 : -ENOMEM;
}

static struct file_system_type secretmem_fs = {
	.name		= "secretmem",
	.init_fs_context = secretmem_init_fs_context,
	.kill_sb	= kill_anon_super,
};

static int secretmem_init(void)
{
	int ret = 0;

	secretmem_mnt = kern_mount(&secretmem_fs);
	if (IS_ERR(secretmem_mnt))
		ret = PTR_ERR(secretmem_mnt);

	return ret;
}
fs_initcall(secretmem_init);
