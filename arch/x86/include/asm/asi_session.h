/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_X86_MM_ASI_SESSION_H
#define ARCH_X86_MM_ASI_SESSION_H

#ifdef CONFIG_ADDRESS_SPACE_ISOLATION

struct asi;

struct asi_session {
	struct asi		*asi;		/* ASI for this session */
	unsigned long		isolation_cr3;	/* cr3 when ASI is active */
	unsigned long		original_cr3;	/* cr3 before entering ASI */
};

#endif	/* CONFIG_ADDRESS_SPACE_ISOLATION */

#endif
