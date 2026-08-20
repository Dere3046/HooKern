// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMHOOK_HK_KPROBE_H
#define LKMHOOK_HK_KPROBE_H

#include <linux/kprobes.h>
#include <linux/types.h>

#define HK_KPROBE_MAX 16

struct hk_kprobe {
	struct kprobe kp;
	unsigned long orig;
};

int hk_kprobe_install(struct hk_kprobe *h, const char *sym,
		      kprobe_pre_handler_t pre);
void hk_kprobe_remove(struct hk_kprobe *h);
void hk_kprobe_exit(void);

int hk_kprobe_clear_blacklist(void);
void hk_kprobe_restore_blacklist(void);

#endif
