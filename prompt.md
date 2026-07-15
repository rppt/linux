We are starting to move to a more "production ready" version.
I created a new branch: direct-map/x86-cpa-based/v0.3 off v7.2-rc1.

WE ARE NOT INTERESETED in the changes from v7.2-rc1 until
direct-map/execmem-fixups/v0.

The overall goal is the same: pull out CPA core from x86 to the common code and
switch riscv and arm64 to use it.

The large steps should be:
* morph existing x86 code to better suite the generic base we want it to be:
  - remove checks debug_pagealloc_enabled() around cpa_lock, there is not much
    sense in reducing locking with debug_pagealloc_enabled()
  - use generic names rather than hard-coded x86-isms
    commit ("20dd926a3b68 dev: x86: set_memory: use generic PGTABLE_LEVEL_*")
    is a good example. The same is relevant for statistics collecton and other
    places that explicitly mention 4k, 2M 1G etc.
    The exceptions are the representation on /proc/iomem and the explict set_4k
    API
  - use page table accessor functions like pte_write, pXd_write, pte_exec,
    pXd_exec instead of hardcoded bit manipulations. Absent accessors should be
    added to arch/x86/include/asm/pgtable.h (or another appropriate header) so
    they'll live alongside existing similar accessors. There should be also a
    stub in include/linux/pgtable.h with BUG(). Look for existing pud_write()
    as an example.
  - for detection of large page size per level implement a generic function
    that switch - cases levels and retuns PMD_SIZE, PUD_SIZE and P4D_SIZE (or
    mask). To accomodate arm64 CONT mappings, this function should get kpte to
    get the actual mapping size
* move alias processing predicates requried to avoid regression to static
  inlines in arch/x86/include/asm/set_memory.h
* pull out CPA core to the common code, add CONFIG_GENERIC_SET_MEMORY and
  enable it in x86, do it gradually:
  - change_page_attr_set_clr and __change_page_attr_set_clr and static
    inlines (similar to commit 1aaec246caef ("Reapply "dev: set_memory: crude
    pull of x86 CPA to mm")). For this step make _lookup_address_cpa available
    to mm/set_memory.c via arch/x86/include/asm/set_memory.h
  - add arch_cpa_info to support opt-pgd_lock on x86; NOTE: I am not sure we'll
    need opt-out of cpa_lock, for arm64 - we'll revise splitting and locking
    there once we get to work on arm64
  - pull lookup_addr variants to the common code along with recheck of the kpte
    in should_split_large_page and split_large_page
* switch riscv to use the generic code:
  - add the necessary page table accessors
  - implement arch_ hooks
  - DO NOT use mmap_lock in riscv, it is superseeded by cpa_lock
* switch arm6 to use the generic code:
  - add the necessary page table accessors
  - implement arch_ hooks
  - NOTE: when bbml is ont available direct (linear) map updates are only
    allowed when can_set_direct_map() is true. However, when bbml IS available,
    arm64 can behave just like x64 and split on the go rather than perform all
    the splits upfront.

As always in kernel, do small, logically contained commits (refresh the skills just in case).
Add my signed-off.
Add your attribution using Assisted-by: agent:model tag.


There are a few updates I need you to do.
Make sure that changes in earlier commits propagete with the moved code.

- Commit bd474f4ed55e ("dev: x86/mm/pat: use generic level names for CPA statistics"):
  * move cpa_inc_checked(level) out of the switch.
  * remove the comment you added in cpa_inc_pte_install()
- Commit 81f92a87ef89 ("dev: x86/mm/pat: use page table accessors for effective RW/NX bits"):
  * restore verify_rwx() to use bits directly, it's staying in x86 anyway
  * in lookup_address_in_pgd_attr() rename local nx to exec and update the logic correspondinly
- Commit 7042b2516a60 ("dev: x86/mm/pat: move cpa_pfn_in_highmap() to asm/set_memory.h"):
  * rename cpa_pfn_in_highmap() to pfn_is_kernel()
  * put #ifdef CONFIG_X86_64 outside the function and add a simple stub for 32-bit
  * restore the comment that was above highmap_start_pfn() and put it above x86-64 variant of pfn_is_kernel()
- Commit 85abacfde79b ("dev: x86/mm/pat: gate alias processing with an inline arch predicate"):
  * rename cpa_alias_needs_update to cpa_should_update_alias()
  * drop mask_set and mask_clr for now, if arm64 or/and riscv need them we'll add them then
  * reduce the wall of text comment you added to a really short gist, preferrably one liner
- Before moving lookup_address functions, add a commit that moves pte recheck under lock to generic should_split_large_page() and split_large_page().
