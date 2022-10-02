// SPDX-License-Identifier: GPL-2.0
/*
 * shstk.c - Intel shadow stack support
 *
 * Copyright (c) 2021, Intel Corporation.
 * Yu-cheng Yu <yu-cheng.yu@intel.com>
 */

#include <linux/sched.h>
#include <linux/bitops.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched/signal.h>
#include <linux/compat.h>
#include <linux/sizes.h>
#include <linux/user.h>
#include <asm/msr.h>
#include <asm/fpu/xstate.h>
#include <asm/fpu/types.h>
#include <asm/cet.h>
#include <asm/special_insns.h>
#include <asm/fpu/api.h>
#include <asm/prctl.h>

#define SS_FRAME_SIZE 8

static bool feature_enabled(unsigned long features)
{
	return current->thread.features & features;
}

static void feature_set(unsigned long features)
{
	current->thread.features |= features;
}

static void feature_clr(unsigned long features)
{
	current->thread.features &= ~features;
}

/*
 * Create a restore token on the shadow stack.  A token is always 8-byte
 * and aligned to 8.
 */
static int create_rstor_token(unsigned long ssp, unsigned long *token_addr)
{
	unsigned long addr;

	/* Token must be aligned */
	if (!IS_ALIGNED(ssp, 8))
		return -EINVAL;

	addr = ssp - SS_FRAME_SIZE;

	/* Mark the token 64-bit */
	ssp |= BIT(0);

	if (write_user_shstk_64((u64 __user *)addr, (u64)ssp))
		return -EFAULT;

	*token_addr = addr;

	return 0;
}

static unsigned long alloc_shstk(unsigned long size)
{
	int flags = MAP_ANONYMOUS | MAP_PRIVATE;
	struct mm_struct *mm = current->mm;
	unsigned long addr, unused;

	mmap_write_lock(mm);
	addr = do_mmap(NULL, addr, size, PROT_READ, flags,
		       VM_SHADOW_STACK | VM_WRITE, 0, &unused, NULL);

	mmap_write_unlock(mm);

	return addr;
}

static void unmap_shadow_stack(u64 base, u64 size)
{
	while (1) {
		int r;

		r = vm_munmap(base, size);

		/*
		 * vm_munmap() returns -EINTR when mmap_lock is held by
		 * something else, and that lock should not be held for a
		 * long time.  Retry it for the case.
		 */
		if (r == -EINTR) {
			cond_resched();
			continue;
		}

		/*
		 * For all other types of vm_munmap() failure, either the
		 * system is out of memory or there is bug.
		 */
		WARN_ON_ONCE(r);
		break;
	}
}

int shstk_setup(void)
{
	struct thread_shstk *shstk = &current->thread.shstk;
	unsigned long addr, size;

	/* Already enabled */
	if (feature_enabled(CET_SHSTK))
		return 0;

	/* Also not supported for 32 bit */
	if (!cpu_feature_enabled(X86_FEATURE_SHSTK) || in_ia32_syscall())
		return -EOPNOTSUPP;

	size = PAGE_ALIGN(min_t(unsigned long long, rlimit(RLIMIT_STACK), SZ_4G));
	addr = alloc_shstk(size);
	if (IS_ERR_VALUE(addr))
		return PTR_ERR((void *)addr);

	fpu_lock_and_load();
	wrmsrl(MSR_IA32_PL3_SSP, addr + size);
	wrmsrl(MSR_IA32_U_CET, CET_SHSTK_EN);
	fpregs_unlock();

	shstk->base = addr;
	shstk->size = size;
	feature_set(CET_SHSTK);

	return 0;
}

void reset_thread_shstk(void)
{
	memset(&current->thread.shstk, 0, sizeof(struct thread_shstk));
	current->thread.features = 0;
	current->thread.features_locked = 0;
}

int shstk_alloc_thread_stack(struct task_struct *tsk, unsigned long clone_flags,
			     unsigned long stack_size, unsigned long *shstk_addr)
{
	struct thread_shstk *shstk = &tsk->thread.shstk;
	unsigned long addr;

	/*
	 * If shadow stack is not enabled on the new thread, skip any
	 * switch to a new shadow stack.
	 */
	if (!feature_enabled(CET_SHSTK))
		return 0;

	/*
	 * clone() does not pass stack_size, which was added to clone3().
	 * Use RLIMIT_STACK and cap to 4 GB.
	 */
	if (!stack_size)
		stack_size = min_t(unsigned long long, rlimit(RLIMIT_STACK), SZ_4G);

	/*
	 * For CLONE_VM, except vfork, the child needs a separate shadow
	 * stack.
	 */
	if ((clone_flags & (CLONE_VFORK | CLONE_VM)) != CLONE_VM)
		return 0;


	stack_size = PAGE_ALIGN(stack_size);
	if (IS_ERR_VALUE(addr))
		return PTR_ERR((void *)addr);

	shstk->base = addr;
	shstk->size = stack_size;

	*shstk_addr = addr + stack_size;

	return 0;
}

static unsigned long get_user_shstk_addr(void)
{
	unsigned long long ssp;

	fpu_lock_and_load();

	rdmsrl(MSR_IA32_PL3_SSP, ssp);

	fpregs_unlock();

	return ssp;
}

static int put_shstk_data(u64 __user *addr, u64 data)
{
	WARN_ON(data & BIT(63));

	/*
	 * Mark the high bit so that the sigframe can't be processed as a
	 * return address.
	 */
	if (write_user_shstk_64(addr, data | BIT(63)))
		return -EFAULT;
	return 0;
}

static int get_shstk_data(unsigned long *data, unsigned long __user *addr)
{
	unsigned long ldata;

	if (unlikely(get_user(ldata, addr)))
		return -EFAULT;

	if (!(ldata & BIT(63)))
		return -EINVAL;

	*data = ldata & ~BIT(63);

	return 0;
}

/*
 * Verify the user shadow stack has a valid token on it, and then set
 * *new_ssp according to the token.
 */
static int shstk_check_rstor_token(unsigned long *new_ssp)
{
	unsigned long token_addr;
	unsigned long token;

	token_addr = get_user_shstk_addr();
	if (!token_addr)
		return -EINVAL;

	if (get_user(token, (unsigned long __user *)token_addr))
		return -EFAULT;

	/* Is mode flag correct? */
	if (!(token & BIT(0)))
		return -EINVAL;

	/* Is busy flag set? */
	if (token & BIT(1))
		return -EINVAL;

	/* Mask out flags */
	token &= ~3UL;

	/* Restore address aligned? */
	if (!IS_ALIGNED(token, 8))
		return -EINVAL;

	/* Token placed properly? */
	if (((ALIGN_DOWN(token, 8) - 8) != token_addr) || token >= TASK_SIZE_MAX)
		return -EINVAL;

	*new_ssp = token;

	return 0;
}

void shstk_free(struct task_struct *tsk)
{
	struct thread_shstk *shstk = &tsk->thread.shstk;

	if (!cpu_feature_enabled(X86_FEATURE_SHSTK) ||
	    !feature_enabled(CET_SHSTK))
		return;

	/*
	 * When fork() with CLONE_VM fails, the child (tsk) already has a
	 * shadow stack allocated, and exit_thread() calls this function to
	 * free it.  In this case the parent (current) and the child share
	 * the same mm struct.
	 */
	if (!tsk->mm || tsk->mm != current->mm)
		return;

	unmap_shadow_stack(shstk->base, shstk->size);
}

int shstk_disable(void)
{
	if (!cpu_feature_enabled(X86_FEATURE_SHSTK))
		return -EOPNOTSUPP;

	/* Already disabled? */
	if (!feature_enabled(CET_SHSTK))
		return 0;

	fpu_lock_and_load();
	/* Disable WRSS too when disabling shadow stack */
	set_clr_bits_msrl(MSR_IA32_U_CET, 0, CET_SHSTK_EN);
	wrmsrl(MSR_IA32_PL3_SSP, 0);
	fpregs_unlock();

	shstk_free(current);
	feature_clr(CET_SHSTK);

	return 0;
}

long cet_prctl(struct task_struct *task, int option, unsigned long features)
{
	if (option == ARCH_CET_LOCK) {
		task->thread.features_locked |= features;
		return 0;
	}

	/* Don't allow via ptrace */
	if (task != current)
		return -EINVAL;

	/* Do not allow to change locked features */
	if (features & task->thread.features_locked)
		return -EPERM;

	/* Only support enabling/disabling one feature at a time. */
	if (hweight_long(features) > 1)
		return -EINVAL;

	if (option == ARCH_CET_DISABLE) {
		return -EINVAL;
	}

	/* Handle ARCH_CET_ENABLE */
	return -EINVAL;
}
