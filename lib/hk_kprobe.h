// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMHOOK_HK_KPROBE_H
#define LKMHOOK_HK_KPROBE_H

#include <linux/kprobes.h>
#include <linux/types.h>

struct hk_kprobe {
	struct kprobe kp;
	unsigned long orig;
};

/*
 * use kprobe instead of hk_inline_hook when
 *   the target can run on another core while the detour is written, a hot path
 *   like device_add. register_kprobe arms the breakpoint under text_mutex and
 *   cpus_read_lock, the inline primitive writes text with no such cover
 *   the entry window holds an ftrace patch site, hk_inline_probe reports
 *   HK_INLINE_PATCHSITE. the relocator would move a patched call site into the
 *   trampoline and lose it, kprobe leaves the call site to ftrace
 *   the relocator refuses the first instructions, hk_inline_probe reports
 *   HK_INLINE_UNSUPPORTED
 *
 * the price is the handler contract: a probe observes a call, it does not
 * replace the function. a pre handler runs at the entry with the arguments in
 * regs, it can rewrite them, or return 1 and park the pc, see hk_regs_return
 * below. the kernel does not step over the probed instruction by itself, so a
 * handler that returns 1 has to move the pc itself. calling the target from a
 * handler re-enters the same probe, so a full replacement stays an inline hook
 * on a target other cores do not execute during installation
 *
 * every install is tracked in a list and removed again by hk_kprobe_exit, there
 * is no ceiling on the number of live probes and no -ENOSPC. a refused install
 * logs the symbol and the gate and returns the kernel code, -EINVAL for every
 * address gate and -ENOENT for a symbol that does not resolve, -ENODATA when
 * register_kprobe cannot be reached, -ENOMEM when the tracking node cannot be
 * allocated, in which case nothing was registered
 */
int hk_kprobe_install(struct hk_kprobe *h, const char *sym,
		      kprobe_pre_handler_t pre);
/* unregister and drop the tracking node, a second remove is a no op */
void hk_kprobe_remove(struct hk_kprobe *h);
/* unregister every tracked probe, called by hk_exit */
void hk_kprobe_exit(void);

/* drop the blacklist entries, every probe refused with HK_KPROBE_BLACKLISTED
 * needs this first, hk_kprobe_exit restores them */
int hk_kprobe_clear_blacklist(void);
void hk_kprobe_restore_blacklist(void);

/*
 * what the address gates of register_kprobe make of a symbol, see
 * hk_inline_state for the inline counterpart
 */
enum hk_kprobe_state {
	HK_KPROBE_UNRESOLVED = 0,	/* the resolver did not find the symbol */
	HK_KPROBE_UNSUPPORTED,		/* not text, or a cfi preamble symbol */
	HK_KPROBE_BLACKLISTED,		/* kprobe_blacklist, __kprobes or noinstr */
	HK_KPROBE_PATCHSITE,		/* a recorded ftrace call site */
	HK_KPROBE_OK,			/* no address gate matched */
};

struct hk_kprobe_report {
	unsigned long addr;	/* resolver result, 0 when unresolved */
	enum hk_kprobe_state state;
	const char *reason;	/* static string, the caller never owns it */
};

/*
 * the kernel folds every reason it refuses an address into -EINVAL, so a bare
 * return code cannot tell a blacklisted symbol from an ftrace call site or a
 * symbol the resolver never found. this asks the same gates in the same order
 * and names the one that fired. nothing is written, nothing is allocated and
 * it does not sleep, so a live hot path can be judged before it is probed
 *
 * 0 when the report was filled, -EINVAL on a NULL argument. HK_KPROBE_OK means
 * no address gate matched, an install can still fail on a kernel symbol the
 * resolver cannot reach or on a tracking node that cannot be allocated. the
 * same gates guard a kretprobe, register_kretprobe registers a kprobe
 */
int hk_kprobe_check(const char *sym, struct hk_kprobe_report *out);

/*
 * argument and return helpers for a handler on arm64. x0 to x7 carry the first
 * eight arguments at a function entry, x0 carries the return value when a
 * kretprobe handler runs, and the kernel writes the registers back after the
 * handler, so a store to them takes effect
 */
static inline unsigned long hk_regs_arg(const struct pt_regs *regs,
					unsigned int n)
{
	if (n >= 8)
		return 0;
	return regs->regs[n];
}

static inline void hk_regs_set_arg(struct pt_regs *regs, unsigned int n,
				   unsigned long v)
{
	if (n < 8)
		regs->regs[n] = v;
}

static inline unsigned long hk_regs_ret(const struct pt_regs *regs)
{
	return regs->regs[0];
}

static inline void hk_regs_set_ret(struct pt_regs *regs, unsigned long v)
{
	regs->regs[0] = v;
}

static inline unsigned long hk_regs_ip(const struct pt_regs *regs)
{
	return regs->pc;
}

static inline unsigned long hk_regs_lr(const struct pt_regs *regs)
{
	return regs->regs[30];
}

/* a pre handler that returns 1 must step the pc over the probed instruction */
static inline void hk_regs_skip(struct pt_regs *regs)
{
	regs->pc += 4;
}

/*
 * the replacement idiom for a hot target: a pre handler that returns 1 stops the
 * kernel from running the probed instruction, so parking the pc on the link
 * register returns from the target at once with x0 as the result, the way a
 * wrapper would. the prologue of the target has not run yet, so nothing is left
 * to unwind
 *
 *	hk_regs_set_ret(regs, my_device_add(hk_regs_arg(regs, 0)));
 *	hk_regs_return(regs);
 *	return 1;
 */
static inline void hk_regs_return(struct pt_regs *regs)
{
	regs->pc = regs->regs[30];
}

#endif
