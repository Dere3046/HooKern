// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "hk.h"
#include "hk_kprobe.h"

typedef int (*register_kprobe_fn)(struct kprobe *p);
typedef void (*unregister_kprobe_fn)(struct kprobe *p);

static struct hk_kprobe *g_kprobes[HK_KPROBE_MAX];
static DEFINE_SPINLOCK(g_kprobe_lock);

struct hk_blacklist_saved {
	struct kprobe_blacklist_entry *entry;
	unsigned long start_addr;
	unsigned long end_addr;
};

static struct hk_blacklist_saved *g_blacklist_saved;
static size_t g_blacklist_count;
static bool g_blacklist_cleared;
static DEFINE_MUTEX(g_blacklist_lock);

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

int hk_kprobe_clear_blacklist(void)
{
	struct kprobe_blacklist_entry *ent;
	struct list_head *head;
	size_t count = 0;
	size_t i = 0;

	mutex_lock(&g_blacklist_lock);
	if (g_blacklist_cleared) {
		mutex_unlock(&g_blacklist_lock);
		return 0;
	}

	head = (struct list_head *)hk_resolve("kprobe_blacklist");
	if (!head || !hk_ker_addr_ok((unsigned long)head)) {
		mutex_unlock(&g_blacklist_lock);
		return -ENOENT;
	}

	list_for_each_entry(ent, head, list) {
		if (ent->start_addr && ent->end_addr)
			count++;
	}

	if (count) {
		g_blacklist_saved = kcalloc(count, sizeof(*g_blacklist_saved),
					    GFP_KERNEL);
		if (!g_blacklist_saved) {
			mutex_unlock(&g_blacklist_lock);
			return -ENOMEM;
		}
	}

	list_for_each_entry(ent, head, list) {
		if (!ent->start_addr || !ent->end_addr)
			continue;
		g_blacklist_saved[i].entry = ent;
		g_blacklist_saved[i].start_addr = ent->start_addr;
		g_blacklist_saved[i].end_addr = ent->end_addr;
		WRITE_ONCE(ent->start_addr, 0);
		WRITE_ONCE(ent->end_addr, 0);
		i++;
	}

	g_blacklist_count = count;
	g_blacklist_cleared = true;
	pr_info("[lkmhook] kprobe blacklist cleared %zu entries\n", count);
	mutex_unlock(&g_blacklist_lock);
	return 0;
}

void hk_kprobe_restore_blacklist(void)
{
	struct hk_blacklist_saved *s;
	size_t i;

	mutex_lock(&g_blacklist_lock);
	if (!g_blacklist_cleared) {
		mutex_unlock(&g_blacklist_lock);
		return;
	}

	for (i = 0; i < g_blacklist_count; i++) {
		s = &g_blacklist_saved[i];

		if (!s->entry)
			continue;
		WRITE_ONCE(s->entry->start_addr, s->start_addr);
		WRITE_ONCE(s->entry->end_addr, s->end_addr);
	}

	kfree(g_blacklist_saved);
	g_blacklist_saved = NULL;
	g_blacklist_count = 0;
	g_blacklist_cleared = false;
	pr_info("[lkmhook] kprobe blacklist restored\n");
	mutex_unlock(&g_blacklist_lock);
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

	hk_kprobe_restore_blacklist();
}
