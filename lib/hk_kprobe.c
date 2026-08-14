// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/spinlock.h>

#include "hk.h"
#include "hk_kprobe.h"

typedef int (*register_kprobe_fn)(struct kprobe *p);
typedef void (*unregister_kprobe_fn)(struct kprobe *p);

static struct hk_kprobe *g_kprobes[HK_KPROBE_MAX];
static DEFINE_SPINLOCK(g_kprobe_lock);

static __nocfi int call_register_kprobe(struct kprobe *p)
{
	register_kprobe_fn fn;

	fn = (register_kprobe_fn)hk_resolve("register_kprobe");
	if (!fn)
		return -ENODATA;
	return fn(p);
}

static __nocfi void call_unregister_kprobe(struct kprobe *p)
{
	unregister_kprobe_fn fn;

	fn = (unregister_kprobe_fn)hk_resolve("unregister_kprobe");
	if (!fn)
		return;
	fn(p);
}

int hk_kprobe_install(struct hk_kprobe *h, const char *sym,
		      kprobe_pre_handler_t pre)
{
	unsigned long flags;
	int i;
	int ret;

	if (!h || !sym || !pre)
		return -EINVAL;

	memset(h, 0, sizeof(*h));
	h->kp.symbol_name = sym;
	h->kp.pre_handler = pre;

	ret = call_register_kprobe(&h->kp);
	if (ret < 0)
		return ret;
	h->orig = (unsigned long)h->kp.addr;

	spin_lock_irqsave(&g_kprobe_lock, flags);
	for (i = 0; i < HK_KPROBE_MAX; i++) {
		if (!g_kprobes[i]) {
			g_kprobes[i] = h;
			break;
		}
	}
	spin_unlock_irqrestore(&g_kprobe_lock, flags);

	if (i == HK_KPROBE_MAX) {
		pr_warn("[lkmhook] kprobe table full %s\n", sym);
		call_unregister_kprobe(&h->kp);
		return -ENOSPC;
	}

	pr_info("[lkmhook] kprobe %s @ 0x%lx\n", sym, h->orig);
	return 0;
}

void hk_kprobe_remove(struct hk_kprobe *h)
{
	unsigned long flags;
	int i;

	if (!h)
		return;

	call_unregister_kprobe(&h->kp);

	spin_lock_irqsave(&g_kprobe_lock, flags);
	for (i = 0; i < HK_KPROBE_MAX; i++) {
		if (g_kprobes[i] == h) {
			g_kprobes[i] = NULL;
			break;
		}
	}
	spin_unlock_irqrestore(&g_kprobe_lock, flags);
}

void hk_kprobe_exit(void)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&g_kprobe_lock, flags);
	for (i = 0; i < HK_KPROBE_MAX; i++) {
		if (!g_kprobes[i])
			continue;
		call_unregister_kprobe(&g_kprobes[i]->kp);
		g_kprobes[i] = NULL;
	}
	spin_unlock_irqrestore(&g_kprobe_lock, flags);
}
