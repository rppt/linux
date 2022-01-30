// SPDX-License-Identifier: GPL-2.0

#define _GNU_SOURCE

#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <x86intrin.h>

#define SS_SIZE 0x200000

void *create_shstk(void)
{
	return (void *)syscall(__NR_map_shadow_stack, SS_SIZE, SHADOW_STACK_SET_TOKEN);
}

#if (__GNUC__ < 8) || (__GNUC__ == 8 && __GNUC_MINOR__ < 5)
int main(int argc, char *argv[])
{
	printf("SKIP: compiler does not support CET.");
	return 0;
}
#else
void try_shstk(unsigned long new_ssp)
{
	unsigned long ssp0, ssp1;

	printf("pid=%d\n", getpid());
	printf("new_ssp = %lx, *new_ssp = %lx\n",
		new_ssp, *((unsigned long *)new_ssp));

	ssp0 = _get_ssp();
	printf("changing ssp from %lx to %lx\n", ssp0, new_ssp);

	/* Make sure is aligned to 8 bytes */
	if ((ssp0 & 0xf) != 0)
		ssp0 &= -8;

	asm volatile("rstorssp (%0)\n":: "r" (new_ssp));
	asm volatile("saveprevssp");
	ssp1 = _get_ssp();
	printf("ssp is now %lx\n", ssp1);

	ssp0 -= 8;
	asm volatile("rstorssp (%0)\n":: "r" (ssp0));
	asm volatile("saveprevssp");
}

int main(int argc, char *argv[])
{
	void *shstk;

	if (!_get_ssp()) {
		printf("SKIP: shadow stack disabled.");
		return 0;
	}

	shstk = create_shstk();
	if (shstk == MAP_FAILED) {
		printf("FAIL: Error creating shadow stack: %d\n", errno);
		return 1;
	}
	try_shstk((unsigned long)shstk + SS_SIZE - 8);

	printf("PASS.\n");
	return 0;
}
#endif
