// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/spinlock.h>

#include "hk.h"
#include "hk_kretprobe.h"

typedef int (*register_kretprobe_fn)(struct kretprobe *rp);
typedef void (*unregister_kretprobe_fn)(struct kretprobe *rp);

static struct hk_kretprobe *g_kretprobes[HK_KRETPROBE_MAX];
static DEFINE_SPINLOCK(g_kretprobe_lock);

static __nocfi int call_register_kretprobe(struct kretprobe *rp)
{
	register_kretprobe_fn fn;

	fn = (register_kretprobe_fn)hk_resolve("register_kretprobe");
	if (!fn)
		return -ENODATA;
	return fn(rp);
}

static __nocfi void call_unregister_kretprobe(struct kretprobe *rp)
{
	unregister_kretprobe_fn fn;

	fn = (unregister_kretprobe_fn)hk_resolve("unregister_kretprobe");
	if (!fn)
		return;
	fn(rp);
}

int hk_kretprobe_install(struct hk_kretprobe *h, const char *sym,
			 kretprobe_handler_t handler)
{
	unsigned long flags;
	int i;
	int ret;

	if (!h || !sym || !handler)
		return -EINVAL;

	memset(h, 0, sizeof(*h));
	h->rp.kp.symbol_name = sym;
	h->rp.handler = handler;

	ret = call_register_kretprobe(&h->rp);
	if (ret < 0)
		return ret;

	spin_lock_irqsave(&g_kretprobe_lock, flags);
	for (i = 0; i < HK_KRETPROBE_MAX; i++) {
		if (!g_kretprobes[i]) {
			g_kretprobes[i] = h;
			break;
		}
	}
	spin_unlock_irqrestore(&g_kretprobe_lock, flags);

	if (i == HK_KRETPROBE_MAX) {
		pr_warn("[lkmhook] kretprobe table full %s\n", sym);
		call_unregister_kretprobe(&h->rp);
		return -ENOSPC;
	}

	pr_info("[lkmhook] kretprobe %s\n", sym);
	return 0;
}

int hk_kretprobe_install_ex(struct hk_kretprobe *h, const char *sym,
			    kretprobe_handler_t entry,
			    kretprobe_handler_t handler,
			    size_t data_size)
{
	unsigned long flags;
	int i;
	int ret;

	if (!h || !sym || !handler)
		return -EINVAL;

	memset(h, 0, sizeof(*h));
	h->rp.kp.symbol_name = sym;
	h->rp.entry_handler = entry;
	h->rp.handler = handler;
	h->rp.data_size = data_size;

	ret = call_register_kretprobe(&h->rp);
	if (ret < 0)
		return ret;

	spin_lock_irqsave(&g_kretprobe_lock, flags);
	for (i = 0; i < HK_KRETPROBE_MAX; i++) {
		if (!g_kretprobes[i]) {
			g_kretprobes[i] = h;
			break;
		}
	}
	spin_unlock_irqrestore(&g_kretprobe_lock, flags);

	if (i == HK_KRETPROBE_MAX) {
		pr_warn("[lkmhook] kretprobe table full %s\n", sym);
		call_unregister_kretprobe(&h->rp);
		return -ENOSPC;
	}

	return 0;
}

void hk_kretprobe_remove(struct hk_kretprobe *h)
{
	unsigned long flags;
	int i;

	if (!h)
		return;

	call_unregister_kretprobe(&h->rp);

	spin_lock_irqsave(&g_kretprobe_lock, flags);
	for (i = 0; i < HK_KRETPROBE_MAX; i++) {
		if (g_kretprobes[i] == h) {
			g_kretprobes[i] = NULL;
			break;
		}
	}
	spin_unlock_irqrestore(&g_kretprobe_lock, flags);
}

void hk_kretprobe_exit(void)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&g_kretprobe_lock, flags);
	for (i = 0; i < HK_KRETPROBE_MAX; i++) {
		if (!g_kretprobes[i])
			continue;
		call_unregister_kretprobe(&g_kretprobes[i]->rp);
		g_kretprobes[i] = NULL;
	}
	spin_unlock_irqrestore(&g_kretprobe_lock, flags);
}
