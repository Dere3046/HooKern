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

/*
 * the three write paths, chosen per call through the mode field of the flags
 * word. the caller decides, the library only reports what a path did.
 *
 * HK_PATCH_MODE_SLOT opens one fixmap slot of this build and stores through the
 * alias. it is the shortest path and it is correct on every kernel whose fixmap
 * frame is the one the headers of this build describe. a vendor kernel may move
 * that frame or prefill an unused slot entry with a descriptor whose present bit
 * is set and whose frame does not exist, and the alias then faults inside the
 * store. the policy below says what happens when the alias is refused.
 *
 * HK_PATCH_MODE_INSN_PATCH is the kernel's own aarch64_insn_patch_text, which
 * parks the cores, walks patch_map and uses the kernel's own FIX_TEXT_POKE0.
 * it assumes nothing about this build and is the path KernelSU takes.
 *
 * HK_PATCH_MODE_INSN_WRITE is the kernel's aarch64_insn_write, one instruction.
 */
#define HK_PATCH_MODE_SLOT 0
#define HK_PATCH_MODE_INSN_PATCH 1
#define HK_PATCH_MODE_INSN_WRITE 2
/*
 * the slot the kernel's own patch_map uses, FIX_TEXT_POKE0, taken by this
 * library instead of by the kernel. it is the index a vendor kernel is least
 * likely to have moved, the write is byte wide like the slot mode, and the
 * frame check still guards it, which the kernel's own patcher does not do.
 * KernelSU writes through this same slot
 */
#define HK_PATCH_MODE_FIXMAP 3

#define HK_PATCH_FLAGS_MODE(m) (((m) & HK_PATCH_MODE_MASK) << HK_PATCH_MODE_SHIFT)
#define HK_PATCH_FLAGS_SLOT(s) (((s) & HK_PATCH_SLOT_MASK) << HK_PATCH_SLOT_SHIFT)

/*
 * what a refused alias does. the alias is refused when the page table entry of
 * the slot is not the frame the write asked for, which is what a moved fixmap
 * frame or a vendor poison descriptor looks like.
 */
enum hk_slot_policy {
	/* a refusal falls back to the kernel primitive and the slot path stays
	 * off for the rest of the module's life. default */
	HK_SLOT_POLICY_FALLBACK = 0,
	/* a refusal falls back for this write only, a later write tries the
	 * slot path again */
	HK_SLOT_POLICY_RETRY = 1,
	/* the alias is stored through whatever the page table says, the frame
	 * test and the memory range test are both skipped. a poison descriptor
	 * faults in the store, which is the caller's choice to risk */
	HK_SLOT_POLICY_FORCE = 2,
	/* the slot path is never entered, every write takes the kernel
	 * primitive */
	HK_SLOT_POLICY_OFF = 3,
};

enum hk_slot_policy hk_patch_slot_policy(void);
void hk_patch_set_slot_policy(enum hk_slot_policy policy);

/*
 * how the alias is judged before the store. both tests answer whether the alias
 * may be stored through, they differ in what they accept. the frame test is the
 * one that catches a vendor poison descriptor or a slot the kernel remapped to a
 * frame of its own, the present test is the historical behaviour and accepts any
 * entry the page table calls present. pick the one the kernel at hand needs
 */
enum hk_slot_check {
	/* present and mapped to the frame the write asked for. default */
	HK_SLOT_CHECK_FRAME = 0,
	/* present is enough, the historical test */
	HK_SLOT_CHECK_PRESENT = 1,
	/* no test at all: the alias is stored through whatever the entry says and
	 * the page table is not even read. the caller takes the risk */
	HK_SLOT_CHECK_NONE = 2,
};

enum hk_slot_check hk_patch_slot_check(void);
void hk_patch_set_slot_check(enum hk_slot_check check);

/*
 * a target whose own page table entry is already writable is written through
 * the address it was given, which is what the kernel's own patch_map does when
 * the strict rwx configs are off. the alias is then never opened, so no fixmap
 * entry is trusted for that write. default on, set to off to always go through
 * the alias
 */
bool hk_patch_slot_direct(void);
void hk_patch_set_slot_direct(bool on);

/*
 * resolve every symbol the write paths need, in process context. the wrappers
 * below resolve lazily when this was not called, and a lazy resolve can happen
 * inside stop_machine, where the kallsyms walk is not allowed to sleep. call it
 * once from the module init path. returns 0 when the required ones are there and
 * the number of optional ones that are missing
 */
int hk_patch_symbols_init(void);

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
