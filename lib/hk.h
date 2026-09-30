// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMHOOK_HK_H
#define LKMHOOK_HK_H

#include <linux/types.h>

struct hk_cfg {
	unsigned long (*resolve)(const char *name);
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

#endif
