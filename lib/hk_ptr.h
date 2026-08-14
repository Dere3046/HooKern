// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMHOOK_HK_PTR_H
#define LKMHOOK_HK_PTR_H

#include <linux/types.h>

#define HK_PTR_MAX 16

int hk_ptr_hook(void **slot, void *replacement, void **orig_out);
void hk_ptr_unhook(void **slot);
void hk_ptr_exit(void);

#endif
