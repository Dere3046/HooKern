// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMHOOK_HK_INLINE_H
#define LKMHOOK_HK_INLINE_H

#include <linux/types.h>

#define HK_INLINE_ENTRY_MAX 5

struct hk_inline {
	const char *name;
	unsigned long addr;
	unsigned long orig;
	void *mem;
	size_t mem_size;
	u32 window;
	bool disabled;
	u8 saved[HK_INLINE_ENTRY_MAX * 4];
};

int hk_inline_hook(struct hk_inline *h, const char *sym,
		   const char *wrapper_sym);
int hk_inline_disable(struct hk_inline *h);
void hk_inline_free(struct hk_inline *h);
void hk_inline_unhook(struct hk_inline *h);

#endif
