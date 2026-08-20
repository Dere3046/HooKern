// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/printk.h>

#include "hk.h"
#include "hk_ptr.h"
#include "hk_kprobe.h"
#include "hk_kretprobe.h"

static struct hk_cfg g_cfg;

__nocfi noinline unsigned long hk_resolve(const char *name)
{
	if (g_cfg.resolve)
		return g_cfg.resolve(name);
	return 0;
}

int hk_init(const struct hk_cfg *cfg)
{
	if (!cfg || !cfg->resolve)
		return -EINVAL;
	if (g_cfg.resolve)
		return -EALREADY;

	g_cfg = *cfg;
	pr_info("[lkmhook] init\n");
	return 0;
}

void hk_exit(void)
{
	hk_kprobe_exit();
	hk_kretprobe_exit();
	hk_ptr_exit();
	memset(&g_cfg, 0, sizeof(g_cfg));
	pr_info("[lkmhook] exit\n");
}
