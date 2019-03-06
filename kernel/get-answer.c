#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE0(get_answer)
{
	return 42;
}

#define BUF_SIZE 1024

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
