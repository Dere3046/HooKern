// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/errno.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include "hk.h"
#include "hk_kprobe.h"
#include "hk_kretprobe.h"

typedef int (*register_kretprobe_fn)(struct kretprobe *rp);
typedef void (*unregister_kretprobe_fn)(struct kretprobe *rp);

/* one tracking node per live probe, the list has no ceiling */
struct hk_kretprobe_node {
	struct list_head list;
	struct hk_kretprobe *hook;
};

static LIST_HEAD(g_kretprobes);
static DEFINE_SPINLOCK(g_kretprobe_lock);

static __nocfi int call_register_kretprobe(struct kretprobe *rp)
{
	register_kretprobe_fn fn;

	fn = (register_kretprobe_fn)hk_resolve("register_kretprobe");
	if (!fn)
		return -ENODATA;
	return fn(rp);
}

static __nocfi int call_unregister_kretprobe(struct kretprobe *rp)
{
	unregister_kretprobe_fn fn;

	fn = (unregister_kretprobe_fn)hk_resolve("unregister_kretprobe");
	if (!fn)
		return -ENODATA;
	fn(rp);
	return 0;
}

/* register_kretprobe registers a kprobe, the kprobe gates answer for it */
static void hk_kretprobe_fail(const char *sym, int ret)
{
	struct hk_kprobe_report rep;

	if (hk_kprobe_check(sym, &rep))
		return;
	pr_warn("[lkmhook] kretprobe %s failed %d %s\n", sym, ret, rep.reason);
}

/* an unregistered probe on module text is a use after free, say so */
static void hk_kretprobe_drop(struct hk_kretprobe *h)
{
	if (!call_unregister_kretprobe(&h->rp))
		return;
	pr_warn("[lkmhook] kretprobe %s left registered, unregister_kretprobe unresolved\n",
		h->rp.kp.symbol_name ? h->rp.kp.symbol_name : "?");
}

static void hk_kretprobe_track(struct hk_kretprobe_node *node,
			       struct hk_kretprobe *h)
{
	unsigned long flags;

	node->hook = h;
	spin_lock_irqsave(&g_kretprobe_lock, flags);
	list_add(&node->list, &g_kretprobes);
	spin_unlock_irqrestore(&g_kretprobe_lock, flags);
}

/* a tracking node is allocated first, so a probe is never left untracked */
static struct hk_kretprobe_node *hk_kretprobe_node_alloc(const char *sym)
{
	struct hk_kretprobe_node *node;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		pr_warn("[lkmhook] kretprobe %s failed -ENOMEM, no tracking node\n",
			sym);
	return node;
}

int hk_kretprobe_install(struct hk_kretprobe *h, const char *sym,
			 kretprobe_handler_t handler)
{
	struct hk_kretprobe_node *node;
	int ret;

	if (!h || !sym || !handler)
		return -EINVAL;

	node = hk_kretprobe_node_alloc(sym);
	if (!node)
		return -ENOMEM;

	memset(h, 0, sizeof(*h));
	h->rp.kp.symbol_name = sym;
	h->rp.handler = handler;

	ret = call_register_kretprobe(&h->rp);
	if (ret < 0) {
		kfree(node);
		hk_kretprobe_fail(sym, ret);
		return ret;
	}

	hk_kretprobe_track(node, h);
	pr_info("[lkmhook] kretprobe %s\n", sym);
	return 0;
}

int hk_kretprobe_install_ex(struct hk_kretprobe *h, const char *sym,
			    kretprobe_handler_t entry,
			    kretprobe_handler_t handler,
			    size_t data_size)
{
	struct hk_kretprobe_node *node;
	int ret;

	if (!h || !sym || !handler)
		return -EINVAL;

	node = hk_kretprobe_node_alloc(sym);
	if (!node)
		return -ENOMEM;

	memset(h, 0, sizeof(*h));
	h->rp.kp.symbol_name = sym;
	h->rp.entry_handler = entry;
	h->rp.handler = handler;
	h->rp.data_size = data_size;

	ret = call_register_kretprobe(&h->rp);
	if (ret < 0) {
		kfree(node);
		hk_kretprobe_fail(sym, ret);
		return ret;
	}

	hk_kretprobe_track(node, h);
	pr_info("[lkmhook] kretprobe %s\n", sym);
	return 0;
}

void hk_kretprobe_remove(struct hk_kretprobe *h)
{
	struct hk_kretprobe_node *node;
	struct hk_kretprobe_node *found = NULL;
	unsigned long flags;

	if (!h)
		return;

	spin_lock_irqsave(&g_kretprobe_lock, flags);
	list_for_each_entry(node, &g_kretprobes, list) {
		if (node->hook != h)
			continue;
		list_del(&node->list);
		found = node;
		break;
	}
	spin_unlock_irqrestore(&g_kretprobe_lock, flags);

	/* not tracked means not registered, a second remove is a no op */
	if (!found)
		return;

	/* unregister sleeps, it stays outside the list lock */
	hk_kretprobe_drop(h);
	kfree(found);
}

void hk_kretprobe_exit(void)
{
	struct hk_kretprobe_node *node;
	struct hk_kretprobe_node *tmp;
	LIST_HEAD(pending);
	unsigned long flags;

	/* take the list off the lock first, unregister sleeps */
	spin_lock_irqsave(&g_kretprobe_lock, flags);
	list_splice_init(&g_kretprobes, &pending);
	spin_unlock_irqrestore(&g_kretprobe_lock, flags);

	list_for_each_entry_safe(node, tmp, &pending, list) {
		hk_kretprobe_drop(node->hook);
		list_del(&node->list);
		kfree(node);
	}
}
