/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * arch/arm/include/asm/pgtable-2level-types.h
 *
 * Copyright (C) 1995-2003 Russell King
 */
#ifndef _ASM_PGTABLE_2LEVEL_TYPES_H
#define _ASM_PGTABLE_2LEVEL_TYPES_H

#include <asm/types.h>

typedef u32 pteval_t;
typedef u32 pmdval_t;

/*
 * These are used to make use of C type-checking..
 */
typedef struct { pteval_t pte; } pte_t;
typedef struct { pmdval_t pmd; } pmd_t;
typedef struct { pmdval_t pgd[2]; } pgd_t;
typedef struct { pteval_t pgprot; } pgprot_t;

#define pte_val(x)      ((x).pte)
#define pmd_val(x)      ((x).pmd)
#define pgd_val(x)	((x).pgd[0])
#define pgprot_val(x)   ((x).pgprot)

#define __pte(x)        ((pte_t) { (x) } )
#define __pmd(x)        ((pmd_t) { (x) } )
#define __pgprot(x)     ((pgprot_t) { (x) } )

#endif	/* _ASM_PGTABLE_2LEVEL_TYPES_H */
