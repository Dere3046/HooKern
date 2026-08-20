// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMHOOK_HK_LSM_H
#define LKMHOOK_HK_LSM_H

#include <linux/lsm_hooks.h>
#include <linux/types.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#define HK_LSM_HEADS_TYPE struct lsm_static_calls_table
#else
#define HK_LSM_HEADS_TYPE struct security_hook_heads
#endif

struct hk_lsm_layout {
	unsigned long (*resolve)(const char *name);
	int (*type_by_name)(const char *name, u32 *id);
	int (*member_off)(u32 id, const char *member, u32 *bit_off,
			  u32 *bit_sz);
	u32 (*type_size)(u32 id);
};

struct hk_lsm_hook {
	const char *head_name;
	const char *target_name;
	size_t head_offset;
	size_t hook_offset;
	void *replacement;
	void *original;
	struct security_hook_list *entry;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	struct lsm_static_call *scall;
#else
	struct security_hook_list list;
#endif
	int offset;
};

#define HK_LSM_HOOK_INIT(member, target_symbol, replacement_fn, off)          \
	{                                                                      \
		.head_name = #member,                                          \
		.target_name = target_symbol,                                  \
		.head_offset = offsetof(HK_LSM_HEADS_TYPE, member),            \
		.hook_offset = offsetof(struct security_hook_list, hook.member),\
		.replacement = (void *)(replacement_fn),                       \
		.offset = off,                                                 \
	}

int hk_lsm_init(const struct hk_lsm_layout *layout);
void hk_lsm_exit(void);
int hk_lsm_hook(struct hk_lsm_hook *hook);
void hk_lsm_unhook(struct hk_lsm_hook *hook);
int hk_lsm_register(struct hk_lsm_hook *hook);
void hk_lsm_unregister(struct hk_lsm_hook *hook);

#endif
