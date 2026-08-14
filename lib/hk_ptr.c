// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/spinlock.h>

#include "hk_patch.h"
#include "hk_ptr.h"

struct hk_ptr_entry {
	void **slot;
	void *orig;
	bool used;
};

static struct hk_ptr_entry g_ptrs[HK_PTR_MAX];
static DEFINE_SPINLOCK(g_ptr_lock);

int hk_ptr_hook(void **slot, void *replacement, void **orig_out)
{
	void *orig;
	unsigned long flags;
	int i;

	if (!slot || !replacement)
		return -EINVAL;

	spin_lock_irqsave(&g_ptr_lock, flags);

	for (i = 0; i < HK_PTR_MAX; i++) {
		if (g_ptrs[i].used && g_ptrs[i].slot == slot) {
			spin_unlock_irqrestore(&g_ptr_lock, flags);
			return -EEXIST;
		}
	}

	for (i = 0; i < HK_PTR_MAX; i++) {
		if (g_ptrs[i].used)
			continue;
		if (copy_from_kernel_nofault(&orig, slot, sizeof(orig))) {
			spin_unlock_irqrestore(&g_ptr_lock, flags);
			return -EFAULT;
		}
		if (hk_patch_write(slot, (unsigned long)replacement)) {
			spin_unlock_irqrestore(&g_ptr_lock, flags);
			return -EIO;
		}
		g_ptrs[i].slot = slot;
		g_ptrs[i].orig = orig;
		g_ptrs[i].used = true;
		if (orig_out)
			*orig_out = orig;
		spin_unlock_irqrestore(&g_ptr_lock, flags);
		pr_info("[lkmhook] ptr hook %px -> %ps\n", slot, replacement);
		return 0;
	}

	spin_unlock_irqrestore(&g_ptr_lock, flags);
	return -ENOSPC;
}

void hk_ptr_unhook(void **slot)
{
	unsigned long flags;
	int i;

	if (!slot)
		return;

	spin_lock_irqsave(&g_ptr_lock, flags);
	for (i = 0; i < HK_PTR_MAX; i++) {
		if (!g_ptrs[i].used || g_ptrs[i].slot != slot)
			continue;
		hk_patch_write(slot, (unsigned long)g_ptrs[i].orig);
		g_ptrs[i].used = false;
		break;
	}
	spin_unlock_irqrestore(&g_ptr_lock, flags);
}

void hk_ptr_exit(void)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&g_ptr_lock, flags);
	for (i = 0; i < HK_PTR_MAX; i++) {
		if (!g_ptrs[i].used)
			continue;
		hk_patch_write(g_ptrs[i].slot, (unsigned long)g_ptrs[i].orig);
		g_ptrs[i].used = false;
	}
	spin_unlock_irqrestore(&g_ptr_lock, flags);
}
