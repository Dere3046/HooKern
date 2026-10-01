// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h>

#include "hk.h"
#include "hk_ptr.h"
#include "hk_kprobe.h"
#include "hk_kretprobe.h"
#include "hk_sighook.h"
#include "hk_inline.h"
#include "hk_patch.h"

static struct hk_cfg g_cfg;
static bool g_exiting;

struct hk_cfi_scan {
	const char *name;
	size_t len;
	unsigned long addr;
};

static int __nocfi hk_cfi_match(void *data, const char *name,
				struct module *mod, unsigned long addr)
{
	struct hk_cfi_scan *scan = data;

	if (strncmp(name, scan->name, scan->len) == 0 &&
	    name[scan->len] == '$') {
		scan->addr = addr;
		return 1;
	}
	return 0;
}

typedef int (*hk_symbol_walk_fn)(int (*fn)(void *, const char *,
					   struct module *, unsigned long),
				 void *data);

/*
 * the clang CFI build keeps the plain name as a stub and renames the body to
 * name$type, so a caller cannot know the suffix and the symbol table is walked
 * once per miss. the walk itself is resolved through this same function, and one
 * flag keeps that second call from asking for the walk again: without it a kernel
 * whose symbol table cannot be reached recurses until the stack is gone
 */
static bool g_cfi_walking;

static unsigned long __nocfi hk_resolve_cfi(const char *name)
{
	hk_symbol_walk_fn walk;
	struct hk_cfi_scan scan;
	unsigned long addr;

	if (g_cfi_walking)
		return 0;
	g_cfi_walking = true;
	walk = (hk_symbol_walk_fn)hk_resolve("kallsyms_on_each_symbol");
	if (!walk) {
		g_cfi_walking = false;
		return 0;
	}
	scan.name = name;
	scan.len = strlen(name);
	scan.addr = 0;
	walk(hk_cfi_match, &scan);
	g_cfi_walking = false;
	addr = scan.addr;
	return addr;
}

__nocfi noinline unsigned long hk_resolve(const char *name)
{
	unsigned long addr;

	if (!name)
		return 0;
	if (g_cfg.resolve && !g_exiting) {
		addr = g_cfg.resolve(name);
		if (addr && hk_ker_addr_ok(addr))
			return addr;
	}
	addr = hk_resolve_cfi(name);
	if (addr && hk_ker_addr_ok(addr))
		return addr;
	return 0;
}

int hk_init(const struct hk_cfg *cfg)
{
	if (!cfg || !cfg->resolve)
		return -EINVAL;
	if (g_cfg.resolve && !g_exiting)
		return -EALREADY;

	g_cfg = *cfg;
	g_exiting = false;
	hk_patch_set_write(cfg->write);
	/*
	 * resolve the write path symbols here and not on first use: a lazy resolve
	 * inside stop_machine would walk kallsyms from an atomic context
	 */
	hk_patch_init();
	pr_info("[lkmhook] init\n");
	return 0;
}

void hk_exit(void)
{
	/*
	 * called by hk_exit_block in a loop, so a restore that failed is retried.
	 * the flag keeps the injected resolver out of the retry, a consumer that
	 * tears its resolver down before hk_exit_block would otherwise resolve
	 * through a freed pointer, and it is what makes a clean shutdown
	 * initialize again instead of -EALREADY
	 */
	g_exiting = true;
	hk_sighook_exit();
	hk_kprobe_exit();
	hk_kretprobe_exit();
	hk_ptr_exit();
	hk_inline_exit();
	pr_info("[lkmhook] exit\n");
}

/*
 * rmmod unmaps module text and data as soon as the exit path returns, and the
 * entry of a hook that could not be restored still branches into the trampoline
 * allocated here. the module ends its exit path through this instead of
 * returning to its caller while a hook is still live: the detour keeps its
 * bytes, so the kernel stays correct, and the rmmod request is the only thing
 * that is refused. it never returns
 */
void hk_exit_block(void)
{
	unsigned int left;

	for (;;) {
		left = hk_inline_pending() + hk_ptr_pending();
		if (!left)
			break;
		pr_warn("[lkmhook] exit blocked, %u hook(s) still live\n", left);
		ssleep(60);
		hk_inline_exit();
		hk_ptr_exit();
	}
	pr_info("[lkmhook] exit clean\n");
	g_exiting = false;
}
