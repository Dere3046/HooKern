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

/*
 * the write into kernel text is not serialized. the patch is several instructions long,
 * its length is reported by the P3 count line at install time, so a core that executes
 * the target while the write happens can run a half written instruction stream.
 *
 * a target that is executing during installation, a device_add style hot path, is
 * therefore not safe to hook. pick a colder function on the same path, or use the kprobe
 * entries, or split prepare from commit so the last write can run from a stop_machine
 * callback. that callback must not sleep and must not allocate, so allocation and symbol
 * resolution have to finish before it.
 */
int hk_inline_hook(struct hk_inline *h, const char *sym,
		   const char *wrapper_sym);
int hk_inline_disable(struct hk_inline *h);
void hk_inline_free(struct hk_inline *h);
void hk_inline_unhook(struct hk_inline *h);

#endif
