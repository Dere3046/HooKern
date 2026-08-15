// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMHOOK_HK_INLINE_H
#define LKMHOOK_HK_INLINE_H

#include <linux/types.h>

#define HK_INLINE_WINDOW_MIN 20
#define HK_INLINE_WINDOW_MAX 32

struct hk_inline {
	const char *name;
	unsigned long addr;
	u32 window;
	void *stub;
	u8 saved[HK_INLINE_WINDOW_MIN];
};

int hk_inline_hook(struct hk_inline *h, const char *sym,
		   const char *stub_sym, const char *wrapper_sym);
void hk_inline_unhook(struct hk_inline *h);

#endif
