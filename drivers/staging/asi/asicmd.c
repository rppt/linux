// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020, Oracle and/or its affiliates.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "asidrv.h"

struct asidrv_test {
	char		*name;		/* test name */
	enum asidrv_seqnum seqnum;	/* sequence */
	bool		asi_active;	/* ASI active at the end of test? */
	char		*desc;		/* test description */
};

struct asidrv_test test_list[] = {
	{ "nop", ASIDRV_SEQ_NOP, true,
	  "enter/exit ASI and nothing else" },
	{ "mem", ASIDRV_SEQ_MEM, false,
	  "enter ASI and accessed an unmapped buffer" },
	{ "memmap", ASIDRV_SEQ_MEMMAP, true,
	  "enter ASI and accessed a mapped buffer" },
	{ "intr", ASIDRV_SEQ_INTERRUPT, true,
	  "receive an interruption while running with ASI" },
	{ "nmi", ASIDRV_SEQ_NMI, true,
	  "receive a NMI while running with ASI" },
	{ "intrnmi", ASIDRV_SEQ_INTRNMI, true,
	  "receive a NMI in an interrupt received while running with ASI" },
	{ "sched", ASIDRV_SEQ_SCHED, true,
	  "call schedule() while running with ASI" },
	{ "printk", ASIDRV_SEQ_PRINTK, true,
	  "call printk() while running with ASI" },
};

#define	TEST_LIST_SIZE	(sizeof(test_list) / sizeof(test_list[0]))

static void usage(void)
{
	int i;

	printf("Usage: asicmd (<cmd>|<test>...)\n");
	printf("\n");
	printf("Commands:\n");
	printf("  all      - run all tests\n");
	printf("\n");
	printf("Tests:\n");
	for (i = 0; i < TEST_LIST_SIZE; i++)
		printf("  %-10s - %s\n", test_list[i].name, test_list[i].desc);
}

static void asidrv_run_test(int fd, struct asidrv_test *test)
{
	struct asidrv_run_param rparam;
	int err;

	printf("Test %s (sequence %d)\n", test->name, test->seqnum);

	rparam.sequence = test->seqnum;

	err = ioctl(fd, ASIDRV_IOCTL_RUN_SEQUENCE, &rparam);

	printf("  - rv = %d ; ", err);
	if (err < 0) {
		printf("error %d\n", errno);
	} else {
		printf("result = %d ; ", rparam.run_error);
		printf("%s\n",
		       rparam.asi_active ? "asi active" : "asi inactive");
	}

	printf("  - expect = %s\n",
	       test->asi_active ? "asi active" : "asi inactive");

	if (err < 0)
		printf("ERROR - error %d\n", errno);
	else if (rparam.run_error != ASIDRV_RUN_ERR_NONE)
		printf("TEST ERROR - error %d\n", rparam.run_error);
	else if (test->asi_active != rparam.asi_active)
		printf("TEST FAILED - unexpected ASI state\n");
	else
		printf("TEST OK\n");
}

int main(int argc, char *argv[])
{
	bool run_all, run;
	int i, j, fd;
	char *test;

	if (argc <= 1) {
		usage();
		return 2;
	}

	fd = open("/dev/asi", O_RDONLY);
	if (fd == -1) {
		perror("open /dev/asi");
		return 1;
	}

	for (i = 1; i < argc; i++) {
		test = argv[i];

		if (!strcmp(test, "all"))
			run_all = true;
		else
			run_all = false;

		run = false;
		for (j = 0; j < TEST_LIST_SIZE; j++) {
			if (run_all || !strcmp(test, test_list[j].name)) {
				asidrv_run_test(fd, &test_list[j]);
				run = true;
			}
		}

		if (!run)
			printf("Unknown test '%s'\n", test);
	}

	close(fd);

	return 0;
}
