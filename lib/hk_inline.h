// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMHOOK_HK_INLINE_H
#define LKMHOOK_HK_INLINE_H

#include <linux/types.h>

#define HK_INLINE_ENTRY_MAX 5

/* bytes the detour overwrites at the entry, the exposure hk_inline_probe reports */
#define HK_INLINE_PATCH_LEN (HK_INLINE_ENTRY_MAX * 4)

struct hk_inline {
	const char *name;
	unsigned long addr;
	unsigned long orig;
	void *mem;
	size_t mem_size;
	u32 window;
	bool disabled;
	u8 saved[HK_INLINE_ENTRY_MAX * 4];
};

/*
 * installs are serialized by a mutex held across trampoline allocation, relocation
 * and the text writes, so two hooks cannot interleave and a restore cannot run inside
 * an install. the write itself is still not atomic: the detour is several instructions
 * long, its length is reported by the P3 count line at install time, so a core that
 * executes the target while the write happens can run a half written instruction stream
 * the lock takes the second writer out, not the reader
 *
 * a target that is executing during installation, a device_add style hot path, is
 * therefore still not safe to hook. use the kprobe entries there, or split prepare from
 * commit so the last write can run from a stop_machine callback. that callback must not
 * sleep and must not allocate, so allocation and symbol resolution have to finish before
 * it, which is why one lock covers them today
 *
 * the detour covers HK_INLINE_PATCH_LEN bytes from the entry, so a target whose symbol is
 * shorter than that shares its window with the next function, and two hooks whose windows
 * overlap each save and restore the other's bytes. the entry needs that much room of its
 * own, hk_inline_probe reports the length it would write
 */
int hk_inline_hook(struct hk_inline *h, const char *sym,
		   const char *wrapper_sym);
/* restore the entry, -EIO when the write fails and the hook stays live */
int hk_inline_disable(struct hk_inline *h);
void hk_inline_free(struct hk_inline *h);
void hk_inline_unhook(struct hk_inline *h);

/*
 * what the entry of a probe target looks like from the outside. everything
 * except plain means the window should not be patched as it stands
 */
enum hk_inline_state {
	HK_INLINE_UNRESOLVED = 0,	/* the symbol did not resolve */
	HK_INLINE_UNREADABLE,		/* the entry window could not be read */
	HK_INLINE_UNSUPPORTED,		/* the relocator refuses the window */
	HK_INLINE_HOOKED,		/* a branch stub sits in the window */
	HK_INLINE_PATCHSITE,		/* an ftrace patch site, the entry is live */
	HK_INLINE_BRANCHED,		/* a direct b in the entry, see target */
	HK_INLINE_PLAIN,		/* no known stub, relocator accepts */
};

struct hk_inline_probe {
	unsigned long addr;	/* resolver result, 0 when unresolved */
	unsigned long target;	/* entry a hook would patch, branch chain followed */
	u32 patch_len;		/* bytes the detour overwrites there, HK_INLINE_PATCH_LEN */
	enum hk_inline_state state;
	const char *reason;	/* static string, the caller never owns it */
};

/*
 * read only half of hk_inline_hook: resolve the symbol, follow the same branch
 * chain, read the entry window through the nofault helper and run the relocator
 * over a copy of it. nothing is written, nothing is allocated and it does not
 * sleep, so a live hot path can be judged before it is patched.
 *
 * the prologue answer is signature based. a known stub comes back hooked, an
 * ftrace patch site comes back patchsite, a direct b comes back branched, and
 * target is the entry a hook would write to: the end of the branch chain when
 * the entry is a thunk the library follows, the entry itself otherwise. an adrp
 * add br stub and a patch that leaves the first instructions alone are not
 * recognised, so plain means no known stub was found, it is not proof of an
 * untouched prologue.
 *
 * 0 when the report was filled, -EINVAL on a NULL argument.
 */
int hk_inline_probe(const char *sym, struct hk_inline_probe *out);

#endif
