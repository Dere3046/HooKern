// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/list.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include "hk_patch.h"
#include "hk_ptr.h"

struct hk_ptr_entry {
	struct list_head list;
	void **slot;
	void *orig;
};

static LIST_HEAD(g_ptrs);
static DEFINE_SPINLOCK(g_ptr_lock);

int hk_ptr_hook(void **slot, void *replacement, void **orig_out)
{
	struct hk_ptr_entry *ent;
	struct hk_ptr_entry *new;
	unsigned long flags;
	void *orig;

	if (!slot || !replacement)
		return -EINVAL;

	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return -ENOMEM;

	spin_lock_irqsave(&g_ptr_lock, flags);

	list_for_each_entry(ent, &g_ptrs, list) {
		if (ent->slot == slot) {
			spin_unlock_irqrestore(&g_ptr_lock, flags);
			kfree(new);
			return -EEXIST;
		}
	}

	if (copy_from_kernel_nofault(&orig, slot, sizeof(orig))) {
		spin_unlock_irqrestore(&g_ptr_lock, flags);
		kfree(new);
		return -EFAULT;
	}
	if (hk_patch_write(slot, (unsigned long)replacement)) {
		spin_unlock_irqrestore(&g_ptr_lock, flags);
		kfree(new);
		return -EIO;
	}

	new->slot = slot;
	new->orig = orig;
	list_add(&new->list, &g_ptrs);

	spin_unlock_irqrestore(&g_ptr_lock, flags);

	if (orig_out)
		*orig_out = orig;
	pr_info("[lkmhook] ptr hook %px -> %ps\n", slot, replacement);
	return 0;
}

void hk_ptr_unhook(void **slot)
{
	struct hk_ptr_entry *ent;
	struct hk_ptr_entry *tmp;
	unsigned long flags;

	if (!slot)
		return;

	spin_lock_irqsave(&g_ptr_lock, flags);
	list_for_each_entry_safe(ent, tmp, &g_ptrs, list) {
		if (ent->slot != slot)
			continue;
		hk_patch_write(slot, (unsigned long)ent->orig);
		list_del(&ent->list);
		spin_unlock_irqrestore(&g_ptr_lock, flags);
		kfree(ent);
		return;
	}
	spin_unlock_irqrestore(&g_ptr_lock, flags);
}

void hk_ptr_exit(void)
{
	struct hk_ptr_entry *ent;
	struct hk_ptr_entry *tmp;
	unsigned long flags;

	spin_lock_irqsave(&g_ptr_lock, flags);
	list_for_each_entry_safe(ent, tmp, &g_ptrs, list) {
		hk_patch_write(ent->slot, (unsigned long)ent->orig);
		list_del(&ent->list);
		kfree(ent);
	}
	spin_unlock_irqrestore(&g_ptr_lock, flags);
}
