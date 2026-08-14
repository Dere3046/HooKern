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

int hk_init(const struct hk_cfg *cfg);
void hk_exit(void);
unsigned long hk_resolve(const char *name);

#endif
