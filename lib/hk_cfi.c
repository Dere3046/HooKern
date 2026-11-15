// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "hk.h"
#include "hk_patch.h"
#include "hk_cfi.h"

#define HK_CFI_RET 0xD65F03C0
#define HK_CFI_MOV 0xD2800020

#define HK_CFI_SAVED_MAX 16

struct hk_cfi_saved {
	unsigned long addr;
	u32 orig[2];
	size_t len;
	bool active;
};

static struct hk_cfi_saved g_cfi_saved[HK_CFI_SAVED_MAX];
static int g_cfi_saved_count;

static int hk_patch_ret_addr(const char *what, unsigned long fn)
{
	u32 cur;
	u32 ret = HK_CFI_RET;
	int i;

	if (!fn || !hk_ker_addr_ok(fn))
		return -ENOENT;
	if (copy_from_kernel_nofault(&cur, (void *)fn, sizeof(cur)))
		return -EFAULT;
	if (cur == ret)
		return 0;

	for (i = 0; i < g_cfi_saved_count; i++) {
		if (g_cfi_saved[i].addr == fn)
			break;
	}
	if (i == g_cfi_saved_count && g_cfi_saved_count < HK_CFI_SAVED_MAX) {
		g_cfi_saved[i].addr = fn;
		g_cfi_saved[i].orig[0] = cur;
		g_cfi_saved[i].len = 4;
		g_cfi_saved[i].active = true;
		g_cfi_saved_count++;
	}

	hk_write_text((void *)fn, &ret, 4);
	pr_info("[lkmhook] cfi bypass %s\n", what);
	return 0;
}

static int hk_patch_ret(const char *name)
{
	return hk_patch_ret_addr(name, hk_resolve(name));
}

static int hk_patch_mov_ret_addr(const char *what, unsigned long fn)
{
	u32 mov_ret[2] = { HK_CFI_MOV, HK_CFI_RET };
	u32 cur[2];
	int i;

	if (!fn || !hk_ker_addr_ok(fn))
		return -ENOENT;
	if (copy_from_kernel_nofault(cur, (void *)fn, sizeof(cur)))
		return -EFAULT;
	if (cur[0] == mov_ret[0] && cur[1] == mov_ret[1])
		return 0;

	for (i = 0; i < g_cfi_saved_count; i++) {
		if (g_cfi_saved[i].addr == fn)
			break;
	}
	if (i == g_cfi_saved_count && g_cfi_saved_count < HK_CFI_SAVED_MAX) {
		g_cfi_saved[i].addr = fn;
		g_cfi_saved[i].orig[0] = cur[0];
		g_cfi_saved[i].orig[1] = cur[1];
		g_cfi_saved[i].len = 8;
		g_cfi_saved[i].active = true;
		g_cfi_saved_count++;
	}

	hk_write_text((void *)fn, mov_ret, sizeof(mov_ret));
	pr_info("[lkmhook] cfi bypass %s\n", what);
	return 0;
}

void hk_cfi_exit(void)
{
	int i;

	for (i = 0; i < g_cfi_saved_count; i++) {
		if (!g_cfi_saved[i].active || !g_cfi_saved[i].addr)
			continue;
		hk_write_text((void *)g_cfi_saved[i].addr, g_cfi_saved[i].orig,
			      g_cfi_saved[i].len);
		g_cfi_saved[i].active = false;
	}
	g_cfi_saved_count = 0;
}

int hk_cfi_bypass(void)
{
	static const char *const ret_syms[] = {
		"cfi_failure_handler",
		"__cfi_check_fail",
		"__ubsan_handle_cfi_check_fail_abort",
		"__ubsan_handle_cfi_check_fail",
		"__cfi_slowpath",
		"__cfi_slowpath_diag",
		"_cfi_slowpath",
	};
	unsigned long fn;
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(ret_syms); i++)
		hk_patch_ret(ret_syms[i]);
	fn = hk_resolve("report_cfi_failure");
	hk_patch_mov_ret_addr("report_cfi_failure", fn);
	return 0;
}
