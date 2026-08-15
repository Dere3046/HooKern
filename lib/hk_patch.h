// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMHOOK_HK_PATCH_H
#define LKMHOOK_HK_PATCH_H

#include <linux/types.h>

#define HK_PATCH_FLUSH_ICACHE 1
#define HK_PATCH_FLUSH_DCACHE 2

int hk_patch_text(void *dst, const void *src, size_t len, int flags);
int hk_patch_write(void *dst, unsigned long val);
bool hk_patch_guarded(void *addr);

#endif
