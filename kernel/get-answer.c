#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/syscalls.h>
#include <linux/hugetlb.h>
#include <asm/special_insns.h>

SYSCALL_DEFINE0(get_answer)
{
	return 42;
}

#define BUF_SIZE 1024

static inline void check_entry_cr3(char ch)
{
	char yn = (__native_read_cr3() & (1 << PTI_PGTABLE_SWITCH_BIT2)) ? 'y' : 'n';

	outb('=', 0x3f8);
	outb('=', 0x3f8);
	outb('=', 0x3f8);
	outb('>', 0x3f8);
	outb(' ', 0x3f8);
	outb(ch, 0x3f8);
	outb(':', 0x3f8);
	outb(yn, 0x3f8);
	outb('\n', 0x3f8);
}

typedef void (*foo)(void);


SYSCALL_DEFINE2(ipti_write, const char __user *, ubuf, size_t, count)
{
	char buf[BUF_SIZE];

	if (!ubuf || count >= BUF_SIZE)
		return -EINVAL;

	buf[count] = '\0';
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;

	pr_info("%s\n", buf);

	return count;
}

SYSCALL_DEFINE2(ipti_write_bad, const char __user *, ubuf, size_t, count)
{
	unsigned long addr = (unsigned long)(void *)hugetlb_reserve_pages;
	char buf[BUF_SIZE];
	foo func1;

	check_entry_cr3('a');

	addr += (0xffffffff81199495 - 0xffffffff811993d0);
	func1 = (foo)(void *)addr;
	func1();

	if (!ubuf || count >= BUF_SIZE)
		return -EINVAL;

	buf[count] = '\0';
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;

	check_entry_cr3('b');

	pr_info("%s\n", buf);

	check_entry_cr3('c');

	return count;
}
