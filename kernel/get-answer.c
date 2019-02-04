#include <asm/syscall.h>
#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/syscalls.h>

IPTI_SYSCALL_DEFINE0(get_answer)
{
	return 42;
}
