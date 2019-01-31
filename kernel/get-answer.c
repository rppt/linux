#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE0(get_answer)
{
	pr_info("%s\n", __func__);
	return 42;
}
