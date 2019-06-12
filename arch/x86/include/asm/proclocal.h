/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */
#ifndef _ASM_X86_PROCLOCAL_H
#define _ASM_X86_PROCLOCAL_H

struct mm_struct;

void arch_proclocal_teardown_pages_and_pt(struct mm_struct *mm);

#endif	/* _ASM_X86_PROCLOCAL_H */
