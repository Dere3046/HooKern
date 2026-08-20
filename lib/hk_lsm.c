// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/static_call.h>
#endif

#include "hk.h"
#include "hk_lsm.h"
#include "hk_patch.h"

#define HK_LSM_MAX 16

struct hk_lsm_entry {
	struct hk_lsm_hook *hook;
};

static DEFINE_MUTEX(hk_lsm_lock);
static struct hk_lsm_entry hk_lsm_entries[HK_LSM_MAX];
static const struct hk_lsm_layout *g_layout;
static int hk_lsm_count;

static unsigned long hk_lsm_resolve_one(const char *name)
{
	if (g_layout && g_layout->resolve)
		return g_layout->resolve(name);
	return hk_resolve(name);
}

static unsigned long hk_lsm_resolve(const char *name)
{
	char buf[128];
	unsigned long addr;

	snprintf(buf, sizeof(buf), "%s.cfi_jt", name);
	addr = hk_lsm_resolve_one(buf);
	if (addr)
		return addr;

	snprintf(buf, sizeof(buf), "%s$", name);
	addr = hk_lsm_resolve_one(buf);
	if (addr)
		return addr;

	return hk_lsm_resolve_one(name);
}

static int hk_lsm_off(const char *type, const char *member, size_t *off)
{
	u32 bit_off;
	u32 bit_sz;
	u32 id;
	int ret;

	if (!g_layout || !g_layout->type_by_name || !g_layout->member_off)
		return -EOPNOTSUPP;
	ret = g_layout->type_by_name(type, &id);
	if (ret)
		return ret;
	ret = g_layout->member_off(id, member, &bit_off, &bit_sz);
	if (ret)
		return ret;
	*off = bit_off / 8;
	return 0;
}

static bool hk_lsm_is_tracked(struct hk_lsm_hook *hook)
{
	int i;

	for (i = 0; i < hk_lsm_count; i++) {
		if (hk_lsm_entries[i].hook == hook)
			return true;
	}
	return false;
}

static int hk_lsm_track(struct hk_lsm_hook *hook)
{
	if (hk_lsm_is_tracked(hook))
		return 0;
	if (hk_lsm_count >= HK_LSM_MAX)
		return -ENOSPC;
	hk_lsm_entries[hk_lsm_count++].hook = hook;
	return 0;
}

static void hk_lsm_untrack(struct hk_lsm_hook *hook)
{
	int i;

	for (i = 0; i < hk_lsm_count; i++) {
		if (hk_lsm_entries[i].hook != hook)
			continue;
		hk_lsm_entries[i] = hk_lsm_entries[--hk_lsm_count];
		return;
	}
}

static int hk_lsm_patch_slot(void **slot, void *value)
{
	void *patched = value;
	int ret;

	ret = hk_patch_text(slot, &patched, sizeof(patched),
			    HK_PATCH_FLUSH_DCACHE);
	if (!ret)
		smp_wmb();
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
static int hk_lsm_update_scall(struct lsm_static_call *scall,
			       size_t key_off, size_t tramp_off, void *value)
{
	void *key;
	void *tramp;

	key = *(void **)((char *)scall + key_off);
	tramp = *(void **)((char *)scall + tramp_off);
	__static_call_update((struct static_call_key *)key, tramp, value);
	smp_wmb();
	return 0;
}
#endif

int hk_lsm_hook(struct hk_lsm_hook *hook)
{
	int ret = 0;
	struct security_hook_list *entry;
	void *target;
	const char *target_name;
	size_t hook_off;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	static unsigned long scalls_addr;
	static size_t scalls_count;
	static u32 lsm_max_cnt = 5;
	size_t scall_key_off = offsetof(struct lsm_static_call, key);
	size_t scall_tramp_off = offsetof(struct lsm_static_call, trampoline);
	size_t scall_hl_off = offsetof(struct lsm_static_call, hl);
	size_t scall_active_off = offsetof(struct lsm_static_call, active);
	struct lsm_static_call *scalls;
	struct security_hook_list *selected_entry = NULL;
	struct lsm_static_call *selected_scall = NULL;
	void **selected_slot = NULL;
	void *selected_origin = NULL;
	size_t i;
#else
	unsigned long heads_addr;
	size_t head_off;
	struct hlist_head *head;
	struct hlist_head *head_end;
	struct security_hook_list *selected_entry = NULL;
	void **selected_slot = NULL;
	void *selected_origin = NULL;
#endif

	if (!hook || !hook->replacement)
		return -EINVAL;

	mutex_lock(&hk_lsm_lock);
	if (hook->entry) {
		ret = -EALREADY;
		goto out_unlock;
	}

	target_name = hook->target_name;
	if (!target_name) {
		ret = -EINVAL;
		goto out_unlock;
	}

	target = hook->original;
	if (!target)
		target = (void *)hk_lsm_resolve(target_name);
	if (!target) {
		ret = -ENOENT;
		goto out_unlock;
	}

	hook_off = hook->hook_offset;
	hk_lsm_off("security_hook_list", "hook", &hook_off);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	hk_lsm_off("lsm_static_call", "key", &scall_key_off);
	hk_lsm_off("lsm_static_call", "trampoline", &scall_tramp_off);
	hk_lsm_off("lsm_static_call", "hl", &scall_hl_off);
	hk_lsm_off("lsm_static_call", "active", &scall_active_off);

	if (!scalls_addr)
		scalls_addr = hk_lsm_resolve("static_calls_table");
	if (!scalls_addr) {
		ret = -ENOSYS;
		goto out_unlock;
	}

	if (!scalls_count) {
		unsigned long active_addr;
		u32 active_cnt = 5;

		active_addr = hk_lsm_resolve("lsm_active_cnt");
		if (active_addr)
			active_cnt = *(u32 *)active_addr;
		if (!active_cnt || active_cnt > 20) {
			ret = -EINVAL;
			goto out_unlock;
		}
		lsm_max_cnt = active_cnt;
		scalls_count = sizeof(struct lsm_static_calls_table) /
			       sizeof(struct lsm_static_call);
	}

	scalls = (struct lsm_static_call *)scalls_addr;
	for (i = 0; i < scalls_count; i++) {
		struct lsm_static_call *scall = &scalls[i];
		void **slot;
		void *current_origin;
		int j;

		entry = READ_ONCE(*(struct security_hook_list **)((char *)scall +
								   scall_hl_off));
		if (!entry)
			continue;

		slot = (void **)((char *)entry + hook_off);
		current_origin = READ_ONCE(*slot);

		for (j = 0; j < hk_lsm_count; j++) {
			if (hk_lsm_entries[j].hook->replacement ==
			    current_origin) {
				current_origin =
					hk_lsm_entries[j].hook->original;
				break;
			}
		}

		if (current_origin == hook->replacement) {
			ret = -EALREADY;
			goto out_unlock;
		}
		if (current_origin != target)
			continue;

		if (!hook->offset) {
			selected_entry = entry;
			selected_scall = scall;
			selected_slot = slot;
			selected_origin = current_origin;
		} else {
			size_t hook_idx = (i / lsm_max_cnt + hook->offset) *
					  lsm_max_cnt;

			if (hook_idx >= scalls_count) {
				ret = -EINVAL;
				goto out_unlock;
			}
			scall = &scalls[hook_idx];
			entry = READ_ONCE(*(struct security_hook_list **)((char *)scall +
									   scall_hl_off));
			if (entry) {
				slot = (void **)((char *)entry +
						 hook_off);
				current_origin = READ_ONCE(*slot);
			} else {
				current_origin = NULL;
			}
			if (current_origin == hook->replacement) {
				ret = -EALREADY;
				goto out_unlock;
			}
			selected_entry = entry;
			selected_scall = scall;
			selected_slot = slot;
			selected_origin = current_origin;
		}
		break;
	}

	if (!selected_scall) {
		ret = -ENOENT;
		goto out_unlock;
	}

	ret = hk_lsm_track(hook);
	if (ret)
		goto out_unlock;

	if (hk_lsm_patch_slot(selected_slot, hook->replacement)) {
		ret = -EFAULT;
		goto out_untrack;
	}
	if (hk_lsm_update_scall(selected_scall, scall_key_off,
				scall_tramp_off, hook->replacement)) {
		hk_lsm_patch_slot(selected_slot, selected_origin);
		ret = -EFAULT;
		goto out_untrack;
	}
	if (!selected_origin)
		static_branch_enable(*(struct static_key_false **)((char *)selected_scall +
								   scall_active_off));

	hook->entry = selected_entry;
	hook->scall = selected_scall;
	hook->original = selected_origin;
	pr_info("[lkmhook] lsm patched %s\n", hook->head_name);
#else
	heads_addr = hk_lsm_resolve("security_hook_heads");
	if (!heads_addr) {
		ret = -ENOENT;
		goto out_unlock;
	}
	head_off = hook->head_offset;
	hk_lsm_off("security_hook_heads", hook->head_name, &head_off);
	head = (struct hlist_head *)(heads_addr + head_off);
	head_end = (struct hlist_head *)(heads_addr +
					 sizeof(struct security_hook_heads));

	for (; head < head_end; head++) {
		hlist_for_each_entry(entry, head, list) {
			void **slot = (void **)((char *)entry +
						 hook_off);
			void *current_origin = READ_ONCE(*slot);
			int j;

			for (j = 0; j < hk_lsm_count; j++) {
				if (hk_lsm_entries[j].hook->replacement ==
				    current_origin) {
					current_origin =
						hk_lsm_entries[j].hook->original;
					break;
				}
			}
			if (current_origin == hook->replacement) {
				ret = -EALREADY;
				goto out_unlock;
			}
			if (current_origin == target) {
				selected_entry = entry;
				selected_slot = slot;
				selected_origin = current_origin;
				break;
			}
		}
		if (selected_entry) {
			if (hook->offset) {
				head += hook->offset;
				if (head < (struct hlist_head *)heads_addr ||
				    head >= head_end) {
					ret = -EINVAL;
					goto out_unlock;
				}
				hlist_for_each_entry(entry, head, list) {
					void **slot =
						(void **)((char *)entry +
							  hook_off);
					void *current_origin =
						READ_ONCE(*slot);

					if (current_origin ==
					    hook->replacement) {
						ret = -EALREADY;
						goto out_unlock;
					}
				}
				if (head->first) {
					selected_entry = hlist_entry(
						head->first,
						struct security_hook_list,
						list);
					selected_slot =
						(void **)((char *)selected_entry +
							  hook_off);
					selected_origin = *selected_slot;
				} else {
					selected_entry = &hook->list;
					hook->list.head = head;
					hook->list.list.next = NULL;
					hook->list.list.pprev = &head->first;
					hook->list.lsm = "lkmhook";
					*(void **)((char *)selected_entry +
						   hook_off) =
						hook->replacement;
					selected_slot = (void **)&head->first;
					selected_origin = NULL;
				}
			}
			break;
		}
	}

	if (!selected_entry) {
		ret = -ENOENT;
		goto out_unlock;
	}

	ret = hk_lsm_track(hook);
	if (ret)
		goto out_unlock;

	if (selected_origin)
		ret = hk_lsm_patch_slot(selected_slot, hook->replacement);
	else
		ret = hk_lsm_patch_slot(selected_slot, &hook->list);
	if (ret) {
		ret = -EFAULT;
		goto out_untrack;
	}

	hook->entry = selected_entry;
	hook->original = selected_origin;
	pr_info("[lkmhook] lsm patched %s\n", hook->head_name);
#endif
	goto out_unlock;

out_untrack:
	hk_lsm_untrack(hook);

out_unlock:
	mutex_unlock(&hk_lsm_lock);
	return ret;
}

void hk_lsm_unhook(struct hk_lsm_hook *hook)
{
	size_t hook_off;
	void **slot;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	size_t scall_key_off = offsetof(struct lsm_static_call, key);
	size_t scall_tramp_off = offsetof(struct lsm_static_call, trampoline);
#endif

	mutex_lock(&hk_lsm_lock);

	hook_off = hook->hook_offset;
	hk_lsm_off("security_hook_list", "hook", &hook_off);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	hk_lsm_off("lsm_static_call", "key", &scall_key_off);
	hk_lsm_off("lsm_static_call", "trampoline", &scall_tramp_off);

	if (!hook->entry || !hook->scall) {
		mutex_unlock(&hk_lsm_lock);
		return;
	}
	slot = (void **)((char *)hook->entry + hook_off);
#else
	if (!hook->entry) {
		mutex_unlock(&hk_lsm_lock);
		return;
	}
	if (hook->entry == &hook->list)
		slot = (void **)&hook->list.head->first;
	else
		slot = (void **)((char *)hook->entry + hook_off);
#endif

	if (hk_lsm_patch_slot(slot, hook->original)) {
		pr_warn("[lkmhook] lsm restore failed %s\n",
			hook->head_name ?: "unknown");
		mutex_unlock(&hk_lsm_lock);
		return;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	if (hk_lsm_update_scall(hook->scall, scall_key_off, scall_tramp_off,
				hook->original)) {
		hk_lsm_patch_slot(slot, hook->replacement);
		mutex_unlock(&hk_lsm_lock);
		return;
	}
#endif

	synchronize_rcu();
	hk_lsm_untrack(hook);
	hook->entry = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	hook->scall = NULL;
#endif
	mutex_unlock(&hk_lsm_lock);
	pr_info("[lkmhook] lsm restored %s\n", hook->head_name ?: "unknown");
}

int hk_lsm_register(struct hk_lsm_hook *hook)
{
	return hk_lsm_hook(hook);
}

void hk_lsm_unregister(struct hk_lsm_hook *hook)
{
	hk_lsm_unhook(hook);
}

int hk_lsm_init(const struct hk_lsm_layout *layout)
{
	g_layout = layout;
	pr_info("[lkmhook] lsm init tracked=%d\n", READ_ONCE(hk_lsm_count));
	return 0;
}

void hk_lsm_exit(void)
{
	struct hk_lsm_hook *hooks[HK_LSM_MAX];
	int count;
	int i;

	mutex_lock(&hk_lsm_lock);
	count = hk_lsm_count;
	for (i = 0; i < count; i++)
		hooks[i] = hk_lsm_entries[i].hook;
	mutex_unlock(&hk_lsm_lock);

	for (i = count - 1; i >= 0; i--)
		hk_lsm_unhook(hooks[i]);
	g_layout = NULL;
}
