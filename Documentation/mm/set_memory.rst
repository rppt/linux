.. SPDX-License-Identifier: GPL-2.0

=============================
Kernel mapping attribute APIs
=============================

Attribute changes and debug protection
======================================

``set_memory_*()`` changes attributes of an existing kernel mapping.
The caller owns the memory and must serialize changes to its mappings.
The architecture determines which address ranges and operations are
supported, and which aliases need corresponding changes.

``set_direct_map_invalid_noflush()`` and
``set_direct_map_default_noflush()`` manage the ordinary direct mapping
for hardening and permission reset.  Their page count covers consecutive
physical pages.  A consumer that requires removal of direct-map access
must have ``ARCH_HAS_SET_DIRECT_MAP`` and satisfy any runtime
``can_set_direct_map()`` restriction.  The compatibility stubs on other
architectures do not provide protection.

debug_pagealloc and KFENCE have different ownership and context rules.
They change pre-existing page-sized mappings belonging to their allocator
or pool, without entering the normal CPA preparation path.  KFENCE may
protect a special virtual alias rather than the ordinary direct map.

Where implemented, ``kernel_page_present()`` observes the mapping used by
``page_address()``.  The fallback returns true without inspecting a mapping.
Neither result establishes ownership or authorizes changing protection.

Hibernation excludes whole debug_pagealloc guard blocks in its free-page
bookkeeping, including tails that do not carry ``PageGuard``.  It may
temporarily unprotect a nonpresent source only if
``is_kfence_address(page_address(page))`` proves KFENCE pool membership.
The test includes pool guards and does not depend on object metadata or
whether KFENCE sampling is enabled.

Snapshot copying uses ``kfence_set_page_protection()`` with other CPUs
offline and interrupts disabled.  It retains the architecture's KFENCE
leaf-update and TLB protocol rather than invoking common CPA.  Pages that
are already present remain present, including guards unprotected by fault
handling.  Protected sources are reprotected after copying.  An unexpected
nonpresent source or a protection failure aborts image creation; it is not
interpreted as a zero-filled page.

LoongArch's DMW cannot revoke ordinary direct-map access, so LoongArch does
not select ``ARCH_HAS_SET_DIRECT_MAP`` and cannot enable secretmem.
Its KFENCE pool uses a page-table alias recorded in ``page_address()``.

Common CPA implementation
=========================

Architectures selecting ``GENERIC_SET_MEMORY`` use the common public
entrypoints and walker in ``mm/set_memory.c``.  Ordinary permission
operations are described by ``arch_cpa_operations``: set and clear
protection masks, request flags, and an explicit supported indicator.
An unsupported operation returns ``-EOPNOTSUPP`` rather than being treated
as an empty successful request.

``arch_cpa_prepare()`` receives a private copy of an operation description.
It can normalize runtime-dependent bits or apply architecture address
restrictions before the request reaches the walker.  A supported operation
may become a no-op after this adjustment.  The existing
two-operation ROX fallback is retained when the architecture does not
describe a combined ROX operation.

The walker keeps caller requests in ``cpa_data.flags`` and execution state
in ``cpa_data.state``.  Architecture callbacks handle entry updates, alias
policy, and large-page preservation or splitting.  Split callbacks must
complete any required structural synchronization before subsequent leaf
attribute changes.

Normal CPA preparation purges unused highmem and vmalloc aliases and
takes the ``init_mm`` read lock around the walk.  This preparation is
separate from ``arch_cpa_prepare()`` and may sleep.  The
read lock is released before architecture completion, which may collapse
mappings and require the write lock.

Direct-map noflush requests skip that preparation: vmalloc permission
reset already invokes them around its own alias flush.  They do not take
the ``init_mm`` read lock, but still use the ``cpa_lock``-serialized walker
and may need to allocate split tables.  Therefore,
``_noflush`` is not an atomic-context guarantee.

The architecture's preservation callback uses ``cpa_prepare_split()`` to
revalidate the mapping, calculate geometry and limit the request to that
mapping.  It must retain any architecture-specific page-table lock through
the decision and update.  ``cpa_lock`` remains held during this callback.

Only a request to split leads to allocation.  The core drops ``cpa_lock``
and, if ``CPA_INIT_MM_READ_LOCKED`` is set, the ``init_mm`` read lock around
allocation, then reacquires them in their original order.  The split
callback must use ``cpa_revalidate_mapping()`` before using the saved entry;
unlike ``cpa_prepare_split()``, this does not trim the request or calculate
geometry.  A zero callback return consumes the allocated table.  On a
nonzero return the core frees it: positive requests a retry, negative
propagates an error.

Completion
==========

``CPA_FLUSHTLB`` records that attributes changed; it does not prescribe
the completion policy.  Common code calls ``arch_cpa_finish()`` when
that state is set, including after partial errors.

For ordinary requests, completion performs the architecture's TLB and
cache maintenance.  For ``CPA_NOFLUSH`` requests, successful invalidation
leaves the final revocation flush to the caller.  Required split
synchronization is not deferred by this flag.

Restoration may require a different mechanism.  RISC-V uses its fault
retry notification on RV64 and a synchronous range flush on RV32.
For partial failures, RISC-V flushes before returning an error; x86 leaves
completion of noflush requests to the caller even on error.  An error does
not imply that earlier changes were rolled back.

Cacheability and encryption
===========================

Memory-type reservations and confidential-computing conversions are
protocols, not just PTE masks.  Common entrypoints call architecture
backends for their preparation, update, completion and error handling.
``ARCH_HAS_SET_MEMORY_CACHE`` selects the cacheability backends;
``ARCH_HAS_MEM_ENCRYPT`` selects the encryption backends.

Architecture-internal interfaces for unreserved cache changes, alternate
page tables and machine-check handling retain their specialized contracts.
