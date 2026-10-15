// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMHOOK_HK_H
#define LKMHOOK_HK_H

#include <linux/types.h>

struct hk_cfg {
	unsigned long (*resolve)(const char *name);
	/*
	 * how the library writes text when a caller does not name a path itself,
	 * one of the hk_write_* primitives of hk_patch.h. NULL takes the kernel's
	 * own primitive, which assumes nothing about the headers this module was
	 * built with. the value is read once, in hk_init
	 */
	int (*write)(void *dst, const void *src, size_t len);
};

static inline bool hk_ker_addr_ok(unsigned long v)
{
	return v >= 0xffff000000000000UL;
}

int hk_init(const struct hk_cfg *cfg);
void hk_exit(void);
unsigned long hk_resolve(const char *name);

/*
 * the consumers run their own exit, the library only counts the failures it was
 * told about and keeps the numbers for the next hk_exit. a module whose exit
 * path left kernel text pointing into module memory must not unload, so it calls
 * hk_exit_block at the end of its own exit and never returns
 */
void hk_exit_fail(int count);
unsigned int hk_exit_failed(void);
void hk_exit_block(void);

/*
 * one tasks rcu grace period: what has to pass between the moment code of this
 * module is taken out of a path another core could be running and the moment it is
 * freed. it is the flavour the kernel uses for its own text pokes, the symbol is
 * resolved here, and a kernel without it says so once instead of waiting for
 * nothing. the call inside is indirect and cfi is off for it, a direct call from a
 * consumer needs nothing
 */
void hk_wait_tasks_rcu(void);
#endif
