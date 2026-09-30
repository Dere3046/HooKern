// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMHOOK_HK_PATCH_H
#define LKMHOOK_HK_PATCH_H

#include <linux/list.h>
#include <linux/types.h>

#define HK_PATCH_FLUSH_ICACHE 1
#define HK_PATCH_FLUSH_DCACHE 2

/*
 * flags word: bits 0 to 7 flush, bits 8 to 15 mode, bits 16 to 23 fixmap slot.
 * both fields default to 0, so the plain calls keep the historical behaviour
 */
#define HK_PATCH_MODE_SHIFT 8
#define HK_PATCH_MODE_MASK 0xFF
#define HK_PATCH_SLOT_SHIFT 16
#define HK_PATCH_SLOT_MASK 0xFF
#define HK_PATCH_SLOT_DEFAULT 0

/*
 * the slots a caller may name are the early ioremap window and nothing else.
 * slot 0 is FIX_BTMAP_END, which is __end_of_permanent_fixed_addresses in every
 * build of this series, so the numbering starts above the permanent window and
 * can never land on FIX_TEXT_POKE0, on the kernel's own patch slot, or on
 * FIX_ENTRY_TRAMP_TEXT1 to TEXT4, which is where map_entry_trampoline maps the
 * KPTI entry trampoline and whose page table entry a stray unmap would clear.
 * the window ends at FIX_BTMAP_BEGIN, boot only and unheld afterwards, and the
 * the library takes the first HK_PATCH_SLOT_LIMIT slots starting at 0. a name outside that is
 * refused with -EINVAL before __set_fixmap is called, whose own guard is a
 * BUG_ON.
 *
 * a write opens one slot, stores and unmaps again, and the unmapping is on the
 * only path that mapped it: every failure exits the chunk loop with the slot
 * already dropped, and a failure before the mapping never opened it, so no slot
 * of the kernel's or of another caller is ever cleared
 */
#define HK_PATCH_SLOT_LIMIT 8

#define HK_PATCH_MODE_SLOT 0
#define HK_PATCH_MODE_INSN_PATCH 1
#define HK_PATCH_MODE_INSN_WRITE 2

#define HK_PATCH_INSNS_MAX 32

/*
 * 0 = the fixmap alias a write is about to store through is not inspected, 1 =
 * it is inspected and a destination that is not a mapped fixmap page gets one
 * warning line naming the address and the caller. a destination that is not
 * mapped is what a shifted enum looks like. the check never refuses the write,
 * it is a diagnostic, and the refusal of a bad slot is the range test above.
 * default 1
 */
#ifndef HK_PATCH_DST_CHECK
#define HK_PATCH_DST_CHECK 1
#endif

int hk_patch_text(void *dst, const void *src, size_t len, int flags);
int hk_patch_text_at(void *dst, const void *src, size_t len, int flags,
		     unsigned int slot);
int hk_patch_write(void *dst, unsigned long val);
int hk_patch_write_at(void *dst, unsigned long val, int flags);

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

void hk_patch_set_init(struct hk_patch_set *set);
void hk_patch_set_release(struct hk_patch_set *set);
int hk_patch_prepare(struct hk_patch_set *set, struct hk_patch_hook *hook);
int hk_patch_commit(struct hk_patch_set *set);
int hk_patch_rollback(struct hk_patch_set *set);
unsigned int hk_patch_set_count(const struct hk_patch_set *set);

void hk_flush_icache(unsigned long addr);

#endif
