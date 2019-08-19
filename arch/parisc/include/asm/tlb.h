/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _PARISC_TLB_H
#define _PARISC_TLB_H

#include <asm-generic/tlb.h>

#define __pmd_free_tlb(tlb, pmd, addr)	pmd_free(pmd)
#define __pte_free_tlb(tlb, pte, addr)	pte_free(mm_pgt((tlb)->mm),  pte)

#endif
