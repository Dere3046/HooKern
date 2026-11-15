// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMHOOK_HK_XREF_H
#define LKMHOOK_HK_XREF_H

#include <linux/types.h>

#define HK_SITE_MAX_OFFSETS	8
#define HK_DEFAULT_MAX_INSNS	4096
#define HK_HARD_MAX_INSNS	65536

#define HK_DEFAULT_BRANCH_HOPS	4
#define HK_MAX_BRANCH_HOPS	16

#define HK_SITE_F_TRUNCATED	0x01
#define HK_SITE_F_FAULT		0x02

enum hk_call_state {
	HK_CALL_STATE_UNKNOWN        = 0,
	HK_CALL_STATE_NO_DIRECT_CALL = 1,
	HK_CALL_STATE_LIVE           = 2,
	HK_CALL_STATE_TAIL           = 3,
	HK_CALL_STATE_NOT_FOUND      = 4,
	HK_CALL_STATE_ERROR          = 5,
};

#define HK_CALL_STATE_INLINED HK_CALL_STATE_NO_DIRECT_CALL

struct hk_call_site {
	const char     *caller_name;
	const char     *callee_name;
	unsigned long   caller_addr;
	unsigned long   callee_addr;
	unsigned long   caller_end;
	size_t          caller_size;
	size_t          max_insns;
	unsigned int    max_hops;
	unsigned int    bl_count;
	unsigned int    b_count;
	size_t          scanned_insns;
	enum hk_call_state state;
	u32             flags;
	u32             offsets[HK_SITE_MAX_OFFSETS];
	u32             offset_count;
};

int hk_probe_call_site(struct hk_call_site *site);
int hk_probe_call_sites(struct hk_call_site *sites, size_t count);
unsigned long hk_unwrap_trampoline(unsigned long addr);
unsigned long hk_unwrap_trampoline_depth(unsigned long addr, unsigned int max_hops);

static inline bool hk_is_inlined(const struct hk_call_site *site)
{
	if (!site) {
		return false;
	}
	return site->state == HK_CALL_STATE_NO_DIRECT_CALL;
}

#endif
