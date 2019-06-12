/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */
#ifndef _PROCLOCAL_H
#define _PROCLOCAL_H

#ifdef CONFIG_PROCLOCAL

struct mm_struct;

void *kmalloc_proclocal(size_t size);
void *kzalloc_proclocal(size_t size);
void kfree_proclocal(void *vaddr);

void proclocal_mm_exit(struct mm_struct *mm);
#else  /* !CONFIG_PROCLOCAL */
static inline void *kmalloc_proclocal(size_t size)
{
	return kmalloc(size, GFP_KERNEL);
}

static inline void * kzalloc_proclocal(size_t size)
{
	return kzalloc(size, GFP_KERNEL);
}

static inline void kfree_proclocal(void *vaddr)
{
	kfree(vaddr);
}

static inline void proclocal_mm_exit(struct mm_struct *mm) { }
#endif

#endif /* _PROCLOCAL_H */
