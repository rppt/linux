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

static struct vfsmount *secretmem_mnt;

#define SECUREMEM 0x2d
#define SET_EXCLUSIVE	_IOW(SECUREMEM, 0x13, unsigned long)
#define SET_UNCACHED	_IOW(SECUREMEM, 0x14, unsigned long)

#define SECRETMEM_EXCLUSIVE	0x23
#define SECRETMEM_UNCACHED	0x24

static struct vfsmount *secretmem_mnt;

struct secretmem_state {
	unsigned int mode;
};

/* static struct page *exclusivemem_get_page(struct secretmem_state *state) */
/* { */
/* 	/\* */
/* 	 * FIXME: implement a pool of huge pages to minimize direct map splits */
/* 	 *\/ */
/* 	return alloc_page(GFP_KERNEL); */
/* } */

static vm_fault_t exclusivemem_fault(struct vm_fault *vmf)
{
	struct address_space *mapping = vmf->vma->vm_file->f_mapping;
	pgoff_t offset = vmf->pgoff;
	unsigned long addr;
	struct page *page;

	page = find_or_create_page(mapping, offset, mapping_gfp_mask(mapping));
	if (!page)
		return vmf_error(-ENOMEM);
	addr = (unsigned long)page_address(page);
	/* get_page(page); */
	pr_info("%s: p: %px, addr: %lx\n", __func__, page, addr);
	dump_page(page, "EX_fault");

/* #if 0 */
	/*
	 * FIXME: we cannot really drop the page from the direct map
	 * until we have a way to reinstate it there
	 */
	if (set_direct_map_invalid_noflush(page)) {
		delete_from_page_cache(page);
		return vmf_error(-ENOMEM);
	}

	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
/* #endif */

	vmf->page = page;
	return  VM_FAULT_LOCKED;
}

static void exclusivemem_close(struct vm_area_struct *vma)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct page *page;
	pgoff_t index;

	pr_info("%s: \n", __func__ );

	xa_for_each(&mapping->i_pages, index, page) {
		unsigned long addr;

		addr = (unsigned long)page_address(page);
		pr_info("%s: p: %px, addr: %lx\n", __func__, page, addr);
		get_page(page);
		lock_page(page);
		dump_page(page, "EX_close 1");
		set_direct_map_default_noflush(page);
		delete_from_page_cache(page);
		unlock_page(page);
		put_page(page);
		dump_page(page, "EX_close 2");

		{
			unsigned int level;

			lookup_address(addr, &level);
			pr_info("%s: level:%d\n", __func__, level);
		}
	}
}

static const struct vm_operations_struct exclusivemem_vm_ops = {
	.fault = exclusivemem_fault,
	.close = exclusivemem_close,
};

static vm_fault_t uncached_fault(struct vm_fault *vmf)
{
	struct address_space *mapping = vmf->vma->vm_file->f_mapping;
	pgoff_t offset = vmf->pgoff;
	unsigned long addr;
	struct page *page;

	page = find_or_create_page(mapping, offset, mapping_gfp_mask(mapping));
	if (!page)
		return vmf_error(-ENOMEM);
	addr = (unsigned long)page_address(page);
	/* get_page(page); */
	pr_info("%s: p: %px, addr: %lx\n", __func__, page, addr);
	dump_page(page, "UC_fault");

	vmf->page = page;
	return  VM_FAULT_LOCKED;

	/* struct page *page; */

	/* page = alloc_page(GFP_HIGHUSER_MOVABLE); */
	/* if (!page) */
	/* 	return vmf_error(-ENOMEM); */

	/* vmf->page = page; */
	/* return 0; */
}

static void uncached_close(struct vm_area_struct *vma)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct page *page;
	pgoff_t index;

	pr_info("%s: \n", __func__ );

	xa_for_each(&mapping->i_pages, index, page) {
		unsigned long addr;

		addr = (unsigned long)page_address(page);
		pr_info("%s: p: %px, addr: %lx\n", __func__, page, addr);
		get_page(page);
		lock_page(page);
		dump_page(page, "EX_close 1");
		set_memory_wb(addr, 1);
		delete_from_page_cache(page);
		unlock_page(page);
		put_page(page);
		dump_page(page, "EX_close 2");

		{
			unsigned int level;

			lookup_address(addr, &level);
			pr_info("%s: level:%d\n", __func__, level);
		}
	}
}

static const struct vm_operations_struct uncached_vm_ops = {
	.fault = uncached_fault,
	.close = uncached_close,
};

static int secretmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct secretmem_state *state = file->private_data;
	unsigned long mode = state->mode;

	switch (mode) {
	case SECRETMEM_EXCLUSIVE:
		vma->vm_ops = &exclusivemem_vm_ops;
		break;
	case SECRETMEM_UNCACHED:
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		vma->vm_ops = &uncached_vm_ops;
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
	case SET_EXCLUSIVE:
		mode = SECRETMEM_EXCLUSIVE;
		break;
	case SET_UNCACHED:
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

/* static int secretmem_open(struct inode *inode, struct file *file) */
/* { */
/* 	struct secretmem_state *state; */
/* 	struct inode *anon_inode; */
/* 	int ret = 0; */

/* 	pr_info("%s: &inode->i_data: %px, inode->i_mapping: %px\n", __func__, &inode->i_data, inode->i_mapping); */
/* 	pr_info("%s: inode->a_ops: %px, empty_aops: %px\n", __func__, inode->i_mapping->a_ops, &empty_aops); */

/* 	state = kzalloc(sizeof(*state), GFP_KERNEL); */
/* 	if (!state) */
/* 		return -ENOMEM; */

/* 	anon_inode = alloc_anon_inode(secretmem_mnt->mnt_sb); */
/* 	if (IS_ERR(anon_inode)) { */
/* 		ret = PTR_ERR(anon_inode); */
/* 		goto err_alloc_inode; */
/* 	} */

/* 	state->inode = inode; */

/* 	address_space_init_once(&state->mapping); */

/* 	state->mapping.a_ops = &empty_aops; */
/* 	state->mapping.host = anon_inode; */
/* 	mapping_set_gfp_mask(&state->mapping, GFP_HIGHUSER_MOVABLE); */
/* 	mapping_set_unevictable(&state->mapping); */

/* 	anon_inode->i_mapping = &state->mapping; */
/* 	anon_inode->i_private = state; */

/* 	file->f_inode = anon_inode; */
/* 	file->f_mapping = anon_inode->i_mapping; */
/* 	file->private_data = state; */

/* 	return 0; */

/* err_alloc_inode: */
/* 	kfree(state); */
/* 	return ret; */
/* } */

const struct file_operations secretmem_fops = {
	.release	= secretmem_release,
	.mmap		= secretmem_mmap,
	.unlocked_ioctl = secretmem_ioctl,
	.compat_ioctl	= secretmem_ioctl,
};

#define SECRETMEM_MODE_MASK	(MFD_SECRET_UNCACHED | MFD_SECRET_EXCLUSIVE)

static int secretmem_setup_mode(struct secretmem_state *state,
				unsigned int flags)
{
	unsigned int mode = flags & SECRETMEM_MODE_MASK;

	switch (mode) {
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

struct file *secretmem_file_create(const char *name, unsigned int flags)
{
	struct inode *inode = alloc_anon_inode(secretmem_mnt->mnt_sb);
	struct file *file = ERR_PTR(-ENOMEM);
	struct secretmem_state *state;
	int err;

	if (IS_ERR(inode))
		return ERR_CAST(inode);

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		goto err_free_inode;

	err = secretmem_setup_mode(state, flags);
	if (err)
		goto err_free_state;

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
