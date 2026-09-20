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

Snapshot page selection is unchanged.  To copy a nonpresent source,
``safe_copy_page()`` uses ``kfence_set_page_protection()`` for KFENCE pool
pages, or the debug_pagealloc mapping hooks when debug_pagealloc is enabled.
KFENCE pool membership is determined by
``is_kfence_address(page_address(page))``, including guards, independently
of object metadata or whether sampling is enabled.

Other CPUs are offline and interrupts are disabled during copying.
The debug hooks retain their architecture's mapping and TLB protocol
rather than invoking common CPA.  Pages that are already present remain
present, including KFENCE guards unprotected by fault handling.
Nonpresent sources are mapped for copying and unmapped again afterwards.
If neither debug path applies, or KFENCE cannot change protection, image
creation fails rather than treating the error as a zero-filled page.

LoongArch's DMW cannot revoke ordinary direct-map access, so LoongArch does
not select ``ARCH_HAS_SET_DIRECT_MAP`` and cannot enable secretmem.
Its KFENCE pool uses a page-table alias recorded in ``page_address()``.

Common CPA implementation
=========================

Architectures selecting ``GENERIC_SET_MEMORY`` use the common walker in
``mm/set_memory.c``.  Ordinary RO/RW/X/NX permission operations and
direct-map default/invalid operations are described by
``arch_cpa_actions``: set and clear protection masks, request flags,
and an explicit supported indicator.  An unsupported operation returns
``-EOPNOTSUPP`` rather than being treated as an empty successful request.

``arch_cpa_prepare()`` runs immediately before the walk and receives the
``cpa_data`` describing it.  It can normalize runtime-dependent bits, apply
architecture address restrictions, or start a batched page table update.  A
supported operation may become a no-op after this adjustment.

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
revalidate the mapping and limit the request to that mapping.  It must
retain any architecture-specific page-table lock through the decision and
update.  ``cpa_lock`` remains held during this callback.

Only a request to split leads to allocation.  The core drops ``cpa_lock``
and, when walking under the ``init_mm`` read lock, drops that lock around
allocation, then reacquires them in their original order.  The split
callback must use ``cpa_revalidate_mapping()`` before using the saved entry;
unlike ``cpa_prepare_split()``, this does not trim the request or calculate
the mapping size.  A zero callback return consumes the allocated table.  On a
nonzero return the core frees it: positive requests a retry, negative
propagates an error.

Completion
==========

``CPA_ST_FLUSHTLB`` records that attributes changed; it does not prescribe
the completion policy.  Common code always calls a completion hook, so that
it also terminates whatever ``arch_cpa_prepare()`` started, and the
architecture decides what an unchanged mapping requires.

For ordinary requests, completion performs the architecture's TLB
maintenance in ``arch_cpa_finish()``.

Direct-map updates complete in ``arch_cpa_finish_direct_map()``, which
does nothing unless the architecture overrides it.  Their callers batch
the TLB flush, so the hook only performs what the architecture requires
before that flush.  Required split synchronization is not deferred.

Restoring the direct map may still need a different mechanism.  RISC-V
uses its fault retry notification on RV64 and a synchronous range flush on
RV32.  An error does not imply that earlier changes were rolled back.

Memory-type reservations and confidential-computing conversions are
protocols, not just PTE masks.  Cacheability and encryption entrypoints
remain architecture-owned, along with architecture-internal interfaces for
unreserved cache changes, alternate page tables and machine-check handling.
