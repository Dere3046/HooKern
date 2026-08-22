// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMHOOK_HK_KRETPROBE_H
#define LKMHOOK_HK_KRETPROBE_H

#include <linux/kprobes.h>
#include <linux/types.h>

#define HK_KRETPROBE_MAX 16

struct hk_kretprobe {
	struct kretprobe rp;
};

int hk_kretprobe_install(struct hk_kretprobe *h, const char *sym,
			 kretprobe_handler_t handler);
int hk_kretprobe_install_ex(struct hk_kretprobe *h, const char *sym,
			    kretprobe_handler_t entry,
			    kretprobe_handler_t handler,
			    size_t data_size);
void hk_kretprobe_remove(struct hk_kretprobe *h);
void hk_kretprobe_exit(void);

#endif
