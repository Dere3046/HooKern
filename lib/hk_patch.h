// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMHOOK_HK_PATCH_H
#define LKMHOOK_HK_PATCH_H

#include <linux/list.h>
#include <linux/types.h>

#define HK_PATCH_INSNS_MAX 32

/*
 * writing kernel text. the library owns the mechanisms and nothing else: which
 * one a call takes is decided at the call site, and whether a write is verified
 * before it lands is decided there too. there is no mode word and no process
 * wide setting, so one look at a call tells the whole story
 *
 * every primitive writes len bytes at dst, cleans the data cache over the range
 * and invalidates the instruction cache, and leaves no mapping behind on any
 * path, including the failing ones. the return value is 0 or a negative errno
 *
 * hk_write_kernel is the kernel's own aarch64_insn_patch_text: it parks the cores
 * and maps through the kernel's own fixmap frame, so it assumes nothing about the
 * headers this module was built with. hk_write_fixmap maps a slot of this build
 * itself, which is the byte wide path and the faster one.
 * hk_write_direct stores where the kernel already mapped the page writable, and
 * hk_va_writable is the test that says whether that is the case
 *
 * a caller that wants a fallback, a retry, or a permanent switch of path writes
 * that in its own wrapper. the library keeps no such state
 */
int hk_write_text(void *dst, const void *src, size_t len);
int hk_write_kernel(void *dst, const void *src, size_t len);
int hk_write_one(void *dst, u32 insn);
int hk_write_fixmap(void *dst, const void *src, size_t len);
int hk_write_fixmap_raw(void *dst, const void *src, size_t len);
int hk_write_direct(void *dst, const void *src, size_t len);

/*
 * what a caller needs to judge a destination itself. the frame test the verified
 * slot path runs is the same one hk_va_maps answers
 */
unsigned long hk_va_to_pa(unsigned long va);
bool hk_va_writable(unsigned long va);
bool hk_va_maps(unsigned long va, unsigned long pa);

void hk_flush_icache(unsigned long addr);
void hk_flush_dcache(unsigned long addr, size_t len);

/*
 * one patch site a transaction covers. the raw bytes read at prepare time are
 * kept and checksummed, the commit refuses to write when the bytes at the
 * address changed since, so a site another writer already took is reported
 * instead of being overwritten
 */
struct hk_patch_hook {
	struct list_head list;
	const char *name;
	void *dst;
	const void *src;
	size_t len;
	int flags;
	u8 orig[HK_PATCH_INSNS_MAX * 4];
	u32 checksum;
	bool prepared;
	bool active;
};

struct hk_patch_set {
	struct list_head hooks;
	struct list_head list;
	unsigned int count;
};

/*
 * the transaction writes through the path hk_init was configured with, one word
 * at a time, and a hook carries no mode of its own
 */
void hk_patch_set_init(struct hk_patch_set *set);
void hk_patch_set_release(struct hk_patch_set *set);
int hk_patch_prepare(struct hk_patch_set *set, struct hk_patch_hook *hook);
int hk_patch_commit(struct hk_patch_set *set);
int hk_patch_rollback(struct hk_patch_set *set);
unsigned int hk_patch_set_count(const struct hk_patch_set *set);

/*
 * the configured path for one unsigned long, which is what a table entry needs
 */
int hk_patch_write(void *dst, unsigned long val);

/*
 * called by hk_init, not by consumers: resolve what the primitives need, in
 * process context, and record the configured write path
 */
void hk_patch_init(void);
void hk_patch_set_write(int (*write)(void *dst, const void *src, size_t len));

#endif
