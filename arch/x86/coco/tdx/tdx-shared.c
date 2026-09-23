#include <linux/pgtable.h>

#include <asm/tdx.h>

static unsigned long try_accept_one(phys_addr_t start, unsigned long len,
				    enum pgtable_level level)
{
	unsigned long accept_size = pgtable_level_size(level);
	struct tdx_module_args args = {};
	u8 page_size;

	if (!IS_ALIGNED(start, accept_size))
		return 0;

	if (len < accept_size)
		return 0;

	/*
	 * Pass the page physical address to the TDX module to accept the
	 * pending, private page.
	 *
	 * Bits 2:0 of RCX encode page size: 0 - 4K, 1 - 2M, 2 - 1G.
	 */
	switch (level) {
	case PGTABLE_LEVEL_PTE:
		page_size = TDX_PS_4K;
		break;
	case PGTABLE_LEVEL_PMD:
		page_size = TDX_PS_2M;
		break;
	case PGTABLE_LEVEL_PUD:
		page_size = TDX_PS_1G;
		break;
	default:
		return 0;
	}

	args.rcx = start | page_size;
	if (__tdcall(TDG_MEM_PAGE_ACCEPT, &args))
		return 0;

	return accept_size;
}

bool tdx_accept_memory(phys_addr_t start, phys_addr_t end)
{
	/*
	 * For shared->private conversion, accept the page using
	 * TDG_MEM_PAGE_ACCEPT TDX module call.
	 */
	while (start < end) {
		unsigned long len = end - start;
		unsigned long accept_size;

		/*
		 * Try larger accepts first. It gives chance to VMM to keep
		 * 1G/2M Secure EPT entries where possible and speeds up
		 * process by cutting number of hypercalls (if successful).
		 */

		accept_size = try_accept_one(start, len, PGTABLE_LEVEL_PUD);
		if (!accept_size)
			accept_size = try_accept_one(start, len, PGTABLE_LEVEL_PMD);
		if (!accept_size)
			accept_size = try_accept_one(start, len, PGTABLE_LEVEL_PTE);
		if (!accept_size)
			return false;
		start += accept_size;
	}

	return true;
}

noinstr u64 __tdx_hypercall(struct tdx_module_args *args)
{
	/*
	 * For TDVMCALL explicitly set RCX to the bitmap of shared registers.
	 * The caller isn't expected to set @args->rcx anyway.
	 */
	args->rcx = TDVMCALL_EXPOSE_REGS_MASK;

	/*
	 * Failure of __tdcall_saved_ret() indicates a failure of the TDVMCALL
	 * mechanism itself and that something has gone horribly wrong with
	 * the TDX module.  __tdx_hypercall_failed() never returns.
	 */
	if (__tdcall_saved_ret(TDG_VP_VMCALL, args))
		__tdx_hypercall_failed();

	/* TDVMCALL leaf return code is in R10 */
	return args->r10;
}
