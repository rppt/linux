// SPDX-License-Identifier: GPL-2.0
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/pseudo_fs.h>
#include <linux/set_memory.h>

#include <asm/tlb.h>

#define SECUREMEM 0xba
#define SET_EXCLUSIVE	_IOWR(SECUREMEM, 0x13, unsigned long)
#define SET_UNCACHED	_IOWR(SECUREMEM, 0x14, unsigned long)

#define SECUREMEM_EXCLUSIVE	0x23
#define SECUREMEM_UNCACHED	0x24

static struct vfsmount *securemem_mnt;

struct securemem_state {
	unsigned long mode;
	struct address_space mapping;
	struct inode *inode;
};

/* static struct page *exclusivemem_get_page(struct securemem_state *state) */
/* { */
/* 	/\* */
/* 	 * FIXME: implement a pool of huge pages to minimize direct map splits */
/* 	 *\/ */
/* 	return alloc_page(GFP_KERNEL); */
/* } */

static vm_fault_t exclusivemem_fault(struct vm_fault *vmf)
{
	struct securemem_state *state = vmf->vma->vm_file->private_data;
	struct address_space *mapping = &state->mapping;
	pgoff_t offset = vmf->pgoff;
	unsigned long addr;
	struct page *page;

	page = find_or_create_page(mapping, offset, mapping_gfp_mask(mapping));
	if (!page)
		return vmf_error(-ENOMEM);
	addr = (unsigned long)page_address(page);
	/* get_page(page); */
	pr_info("%s: p: %px, addr: %lx\n", __func__, page, addr);
	dump_page(page, "excl_fault");

/* #if 0 */
	/*
	 * FIXME: we cannot really drop the page from the direct map
	 * until we have a way to reinstate it there
	 */
	if (set_direct_map_invalid_noflush(page)) {
		__free_page(page);
		return vmf_error(-ENOMEM);
	}

	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
/* #endif */

	vmf->page = page;
	return  VM_FAULT_LOCKED;
}

static void exclusivemem_unmap(struct vm_area_struct *vma, unsigned long start,
			       unsigned long end)
{
	struct securemem_state *state = vma->vm_file->private_data;
	struct address_space *mapping = &state->mapping;
	struct page *page;
	pgoff_t index;

	pr_info("%s: \n", __func__ );

	xa_for_each(&mapping->i_pages, index, page) {
		unsigned long addr;

		addr = (unsigned long)page_address(page);
		pr_info("%s: p: %px, addr: %lx\n", __func__, page, addr);
		dump_page(page, "excl_unmap");
	}
}

static void exclusivemem_close(struct vm_area_struct *vma)
{
	struct securemem_state *state = vma->vm_file->private_data;
	struct address_space *mapping = &state->mapping;
	struct page *page;
	pgoff_t index;

	pr_info("%s: \n", __func__ );

	xa_for_each(&mapping->i_pages, index, page) {
		unsigned long addr;

		addr = (unsigned long)page_address(page);
		pr_info("%s: p: %px, addr: %lx\n", __func__, page, addr);
		get_page(page);
		lock_page(page);
		dump_page(page, "excl_close 1");
		set_direct_map_default_noflush(page);
		delete_from_page_cache(page);
		unlock_page(page);
		put_page(page);
		dump_page(page, "excl_close 2");

		{
			unsigned int level;

			lookup_address(addr, &level);
			pr_info("%s: level:%d\n", __func__, level);
		}
	}
}

static const struct vm_operations_struct exclusivemem_vm_ops = {
	.fault = exclusivemem_fault,
	.unmap = exclusivemem_unmap,
	.close = exclusivemem_close,
};

static vm_fault_t uncached_fault(struct vm_fault *vmf)
{
	struct page *page;

	page = alloc_page(GFP_HIGHUSER_MOVABLE);
	if (!page)
		return vmf_error(-ENOMEM);

	vmf->page = page;
	return 0;
}

static const struct vm_operations_struct uncached_vm_ops = {
	.fault = uncached_fault,
};

static int securemem_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct securemem_state *state = file->private_data;
	unsigned long mode = state->mode;

	switch (mode) {
	case SECUREMEM_EXCLUSIVE:
		vma->vm_ops = &exclusivemem_vm_ops;
		break;
	case SECUREMEM_UNCACHED:
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		vma->vm_ops = &uncached_vm_ops;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static long securemem_ioctl(struct file *file, unsigned cmd, unsigned long arg)
{
	struct securemem_state *state = file->private_data;
	unsigned long mode = state->mode;

	if (mode)
		return -EINVAL;

	switch (cmd) {
	case SET_EXCLUSIVE:
		mode = SECUREMEM_EXCLUSIVE;
		break;
	case SET_UNCACHED:
		mode = SECUREMEM_UNCACHED;
		break;
	default:
		return -EINVAL;
	}

	state->mode = mode;

	return 0;
}

static int securemem_release(struct inode *inode, struct file *file)
{
	struct securemem_state *state = file->private_data;

	file->f_inode = state->inode;

	kfree(state);

	return 0;
}

/* static const struct address_space_operations securemem_aops = { */
/* }; */

static int securemem_open(struct inode *inode, struct file *file)
{
	struct securemem_state *state;
	struct inode *anon_inode;
	int ret = 0;

	pr_info("%s: &inode->i_data: %px, inode->i_mapping: %px\n", __func__, &inode->i_data, inode->i_mapping);
	pr_info("%s: inode->a_ops: %px, empty_aops: %px\n", __func__, inode->i_mapping->a_ops, &empty_aops);

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	anon_inode = alloc_anon_inode(securemem_mnt->mnt_sb);
	if (IS_ERR(anon_inode)) {
		ret = PTR_ERR(anon_inode);
		goto err_alloc_inode;
	}

	state->inode = inode;

	address_space_init_once(&state->mapping);

	state->mapping.a_ops = &empty_aops;
	state->mapping.host = anon_inode;
	mapping_set_gfp_mask(&state->mapping, GFP_HIGHUSER_MOVABLE);
	mapping_set_unevictable(&state->mapping);

	anon_inode->i_mapping = &state->mapping;
	anon_inode->i_private = state;

	file->f_inode = anon_inode;
	file->f_mapping = anon_inode->i_mapping;
	file->private_data = state;

	return 0;

err_alloc_inode:
	kfree(state);
	return ret;
}

const struct file_operations securemem_fops = {
	.open		= securemem_open,
	.release	= securemem_release,
	.mmap		= securemem_mmap,
	.unlocked_ioctl = securemem_ioctl,
	.compat_ioctl	= securemem_ioctl,
};

#define SECUREMEM_MAGIC 0x44

static int securemem_init_fs_context(struct fs_context *fc)
{
	return init_pseudo(fc, SECUREMEM_MAGIC) ? 0 : -ENOMEM;
}

static struct file_system_type securemem_fs = {
	.name		= "securemem",
	.init_fs_context = securemem_init_fs_context,
	.kill_sb	= kill_anon_super,
};

static int securemem_init(void)
{
	int ret = 0;

	securemem_mnt = kern_mount(&securemem_fs);
	if (IS_ERR(securemem_mnt))
		ret = PTR_ERR(securemem_mnt);

	return ret;
}
fs_initcall(securemem_init);
