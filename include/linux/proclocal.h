/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */
#ifndef _PROCLOCAL_H
#define _PROCLOCAL_H

#ifdef CONFIG_PROCLOCAL

struct mm_struct;

void proclocal_mm_exit(struct mm_struct *mm);
#else  /* !CONFIG_PROCLOCAL */
static inline void proclocal_mm_exit(struct mm_struct *mm) { }
#endif

#endif /* _PROCLOCAL_H */
