// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2015, Christoph Hellwig.
 * Copyright (c) 2015, Intel Corporation.
 */
#include <linux/platform_device.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/mm.h>
#include <linux/sched.h>

/*
 * Legacy pmem is usually carved out of RAM with memmap= and may be not
 * accepted yet.
 */
static __init int accept_pmem(struct resource *res, void *data)
{
	resource_size_t start = res->start, end = res->end + 1;
	bool *found = data;

	while (start < end) {
		resource_size_t size = min(end - start, SZ_1G);

		accept_memory(start, size);
		start += size;
		cond_resched();
	}

	*found = true;

	return 0;
}

static __init int register_e820_pmem(void)
{
	struct platform_device *pdev;
	bool found = false;
	int rc;

	walk_iomem_res_desc(IORES_DESC_PERSISTENT_MEMORY_LEGACY,
			    IORESOURCE_MEM, 0, -1, &found, accept_pmem);
	if (!found)
		return 0;

	/*
	 * See drivers/nvdimm/e820.c for the implementation, this is
	 * simply here to trigger the module to load on demand.
	 */
	pdev = platform_device_alloc("e820_pmem", -1);
	if (!pdev)
		return -ENOMEM;

	rc = platform_device_add(pdev);
	if (rc)
		platform_device_put(pdev);

	return rc;
}
device_initcall(register_e820_pmem);
