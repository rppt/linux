// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Test module for KHO
 * Copyright (c) 2024, 2025 Microsoft Corporation.
 *
 * Authors:
 *   Saurabh Sengar <ssengar@microsoft.com>
 *   Mike Rapoport <rppt@kernel.org>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/gfp.h>
#include <linux/kexec.h>
#include <linux/libfdt.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/vmalloc.h>
#include <linux/kexec_handover.h>

#include <net/checksum.h>

#define TEST_KHO_MAGIC	0x4b484f21	/* KHO! */
#define TEST_KHO_ALLOC_ORDER	2
#define TEST_KHO_NR_PAGES	(1 << TEST_KHO_ALLOC_ORDER)
static const size_t mem_size = TEST_KHO_NR_PAGES * PAGE_SIZE;

struct test_kho_state {
	unsigned int magic;
	void *contig_data;
	void *scattered_data;
	__sum16 contig_csum;
	__sum16 scattered_csum;
};

static struct test_kho_state test_kho_state;

static int test_kho_setup(void)
{
	struct test_kho_state *state = &test_kho_state;
	struct page *page;
	void *ptr;

	ptr = vmalloc(mem_size);
	if (!ptr)
		return -ENOMEM;

	page = alloc_pages(GFP_KERNEL, TEST_KHO_ALLOC_ORDER);
	if (!page) {
		vfree(ptr);
		return -ENOMEM;
	}

	state->magic = TEST_KHO_MAGIC;
	state->contig_data = page_address(page);
	state->scattered_data = ptr;

	get_random_bytes(state->contig_data, mem_size);
	get_random_bytes(state->scattered_data, mem_size);

	state->contig_csum = ip_compute_csum(state->contig_data, mem_size);
	state->scattered_csum = ip_compute_csum(state->scattered_data, mem_size);

	return 0;
}

static void __init test_kho_revive_data(const void *fdt)
{
	int node, len;
	const struct kho_mem *mem;
	const __sum16 *csum;
	void *buf;

	node = fdt_path_offset(fdt, "/test_kho/contig_data");
	if (node < 0) {
		pr_warn("no conting data node: %d\n", node);
		return;
	}

	if (fdt_node_check_compatible(fdt, node, "contig_data-v1")) {
		pr_warn("Node /contig_data has unknown compatible");
		return;
	}

	csum = fdt_getprop(fdt, node, "csum", &len);
	if (!csum || len != sizeof(*csum)) {
		pr_warn("contig csum len does not match: %d\n", len);
		return;
	}

	mem = fdt_getprop(fdt, node, "mem", &len);
	buf = kho_claim_mem(mem);
	if (!buf) {
		pr_warn("failed to claim contig_data memory\n");
		return;
	}

	if (*csum != ip_compute_csum(buf, mem_size)) {
		pr_warn("wrong conting_csum want: %x got: %x\n", *csum, ip_compute_csum(buf, mem_size));
		return;
	}

	node = fdt_path_offset(fdt, "/test_kho/scattered_data");
	if (node < 0) {
		pr_warn("no scattered data node\n");
		return;
	}

	if (fdt_node_check_compatible(fdt, node, "scattered_data-v1")) {
		pr_warn("Node /scattered_data has unknown compatible");
		return;
	}

	csum = fdt_getprop(fdt, node, "csum", &len);
	if (!csum || len != sizeof(*csum)) {
		pr_warn("scattered csum len does not match: %d\n", len);
		return;
	}

	mem = fdt_getprop(fdt, node, "mem", &len);
	pr_info("===> %s: len: %d\n", __func__, len);

	buf = vmalloc(mem_size);
	if (!buf) {
		pr_warn("vmalloc failed\n");
		return;
	}

	for (int i = 0; i < len/sizeof(*mem); i++) {
		void *ptr = kho_claim_mem(&mem[i]);

		if (!ptr) {
			pr_warn("failed to claim scattered_data memory\n");
			goto out;
		}

		memcpy(buf + PAGE_SIZE * i, ptr, PAGE_SIZE);
	}

	if (*csum != ip_compute_csum(buf, mem_size)) {
		pr_warn("wrong scattered_csum want: %x got: %x\n", *csum, ip_compute_csum(buf, mem_size));
		return;
	}

	pr_info("all good! :)\n");
out:
	vfree(buf);
}

/**
 * test_kho_revive - Revive test blocks from KHO
 */
static void __init test_kho_revive(const void *fdt)
{
	int node, len;
	const int *num;
	const unsigned int *magic;

	if (!IS_ENABLED(CONFIG_KEXEC_HANDOVER) || !fdt)
		return;

	node = fdt_path_offset(fdt, "/test_kho");
	if (node < 0)
		return;

	if (fdt_node_check_compatible(fdt, node, "test_kho-v1")) {
		pr_warn("Node /test_kho has unknown compatible");
		return;
	}

	magic = fdt_getprop(fdt, node, "magic", &len);
	if (!magic || len != sizeof(*magic))
		return;

	if (*magic != TEST_KHO_MAGIC) {
		pr_err("magic does not match: want: %u got %u\n", TEST_KHO_MAGIC, *magic);
		return;
	}

	num = fdt_getprop(fdt, node, "test-property", &len);
	if (!num || len != sizeof(*num))
		return;

	printk ("value passed from prev kernel: %0x\n", *num);

	test_kho_revive_data(fdt);
}

static int test_kho_save_contig_data(void *fdt)
{
	struct test_kho_state *state = &test_kho_state;
	const char compatible[] = "contig_data-v1";
	struct kho_mem mem = {
		.addr = __pa(state->contig_data),
		.size = mem_size,
	};
	int err = 0;

	err |= fdt_begin_node(fdt, "contig_data");
	err |= fdt_property(fdt, "compatible", compatible, sizeof(compatible));
	err |= fdt_property(fdt, "csum", &state->contig_csum, sizeof(state->contig_csum));
	err |= fdt_property(fdt, "mem", &mem, sizeof(mem));
	err |= fdt_end_node(fdt);

	return err;
}

static int test_kho_save_scattered_data(void *fdt)
{
	struct test_kho_state *state = &test_kho_state;
	const char compatible[] = "scattered_data-v1";
	struct kho_mem *mem;
	size_t mem_len;
	int err = 0;

	mem_len = TEST_KHO_NR_PAGES * sizeof(*mem);
	mem = kmalloc(mem_len, GFP_KERNEL);
	if (!mem)
		return -ENOMEM;

	err |= fdt_begin_node(fdt, "scattered_data");
	err |= fdt_property(fdt, "compatible", compatible, sizeof(compatible));
	err |= fdt_property(fdt, "csum", &state->scattered_csum, sizeof(state->scattered_csum));

	for (int i = 0; i < TEST_KHO_NR_PAGES; i++) {
		void *ptr = state->scattered_data + PAGE_SIZE * i;

		mem[i] = (struct kho_mem){
			.addr = PFN_PHYS(vmalloc_to_pfn(ptr)),
			.size = PAGE_SIZE,
		};
	}

	err |= fdt_property(fdt, "mem", mem, mem_len);
	err |= fdt_end_node(fdt);

	return err;
}

static int test_kho_notifier(struct notifier_block *self, unsigned long cmd, void *v)
{
	const char compatible[] = "test_kho-v1";
	void *fdt = v;
	int err;
	int num = 0xDEADBEEF;

	switch (cmd) {
	case KEXEC_KHO_ABORT:
		return NOTIFY_DONE;
	case KEXEC_KHO_DUMP:
		/* Handled below */
		break;
	default:
		return NOTIFY_BAD;
	}

	err = fdt_begin_node(fdt, "test_kho");
	err |= fdt_property(fdt, "compatible", compatible, sizeof(compatible));
	err |= fdt_property(fdt, "magic", &test_kho_state.magic, sizeof(test_kho_state.magic));
	err |= fdt_property(fdt, "test-property", &num, sizeof(num));
	err |= test_kho_save_contig_data(fdt);
	err |= test_kho_save_scattered_data(fdt);
	err |= fdt_end_node(fdt);

	return err ? NOTIFY_BAD : NOTIFY_DONE;
}

static struct notifier_block test_kho_nb = {
	.notifier_call = test_kho_notifier,
};

static int __init test_kho_init(void)
{
	const void *fdt = kho_get_fdt();
	int err;

	if (fdt) {
		pr_info("trying to revive data from KHO\n");
		test_kho_revive(fdt);
	}

	err = test_kho_setup();
	if (err)
		return err;

	return register_kho_notifier(&test_kho_nb);
}
module_init(test_kho_init);

static void test_kho_cleanup(void)
{
	vfree(test_kho_state.scattered_data);
	free_pages((unsigned long)test_kho_state.contig_data, TEST_KHO_ALLOC_ORDER);
}

static void __exit test_kho_exit(void)
{
	unregister_kho_notifier(&test_kho_nb);
	test_kho_cleanup();
	pr_warn("Goodbye\n");
}
module_exit(test_kho_exit);

MODULE_LICENSE("GPL");
