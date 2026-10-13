// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/errno.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/xarray.h>

#include "hk.h"
#include "hk_inline.h"
#include "hk_kprobe.h"
#include "hk_redir.h"

/*
 * the handler of every kprobe route hook. the probe is a member of the hook, so the
 * hook is what encloses it and one handler serves all of them
 */
static int hk_redir_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct hk_redir *r = container_of(p, struct hk_redir, u.kprobe.kp);

	if (!hk_redir_guard_enter(r))
		return 0;
	hk_regs_redirect(regs, READ_ONCE(r->repl));
	return 1;
}

bool hk_redir_guard_enter(struct hk_redir *r)
{
	void *old;

	if (!r || !READ_ONCE(r->live))
		return false;
	if (xa_load(&r->guard, (unsigned long)current))
		return false;
	/*
	 * the node comes from atomic memory on purpose: the handler runs with the
	 * probed core parked, and a sleeping allocation here is the bug this replaces
	 */
	old = xa_store(&r->guard, (unsigned long)current, r, GFP_ATOMIC);
	return !xa_is_err(old);
}

void hk_redir_leave(struct hk_redir *r)
{
	if (!r)
		return;
	xa_erase(&r->guard, (unsigned long)current);
}

int hk_redir_install_at(struct hk_redir *r, unsigned long addr,
			unsigned long repl, enum hk_redir_how how)
{
	int ret;

	if (!r || !addr || !repl)
		return -EINVAL;
	/* the text route writes an entry it has to read and relocate first */
	if (how != HK_REDIR_KPROBE)
		return -EOPNOTSUPP;

	memset(r, 0, sizeof(*r));
	xa_init(&r->guard);
	r->how = how;
	r->addr = addr;
	r->orig = addr;
	r->repl = repl;
	/*
	 * live before the probe is armed: a call can be redirected the moment
	 * register_kprobe returns, and the handler has to see a hook it may enter
	 */
	r->live = true;

	ret = hk_kprobe_install_at(&r->u.kprobe, addr, hk_redir_pre);
	if (ret) {
		r->live = false;
		xa_destroy(&r->guard);
		return ret;
	}
	return 0;
}

int hk_redir_install(struct hk_redir *r, const char *sym, const char *repl_sym,
		     enum hk_redir_how how)
{
	unsigned long addr;
	unsigned long repl;
	int ret;

	if (!r || !sym || !repl_sym)
		return -EINVAL;

	if (how == HK_REDIR_TEXT) {
		memset(r, 0, sizeof(*r));
		r->how = how;
		r->name = sym;
		r->repl = hk_resolve(repl_sym);
		if (!r->repl)
			return -ENOENT;
		ret = hk_inline_hook(&r->u.text, sym, repl_sym);
		if (ret)
			return ret;
		r->addr = r->u.text.addr;
		r->orig = r->u.text.orig;
		r->live = true;
		return 0;
	}

	addr = hk_resolve(sym);
	if (!addr)
		return -ENOENT;
	repl = hk_resolve(repl_sym);
	if (!repl)
		return -ENOENT;

	ret = hk_redir_install_at(r, addr, repl, how);
	if (ret)
		return ret;
	r->name = sym;
	return 0;
}

int hk_redir_remove(struct hk_redir *r)
{
	int ret;

	if (!r || !r->live)
		return -EINVAL;

	/* from here on a breakpoint that fires runs the original */
	WRITE_ONCE(r->live, false);

	if (r->how == HK_REDIR_TEXT) {
		/* the disable, the grace period and the free, in that order */
		hk_inline_unhook(&r->u.text);
		return 0;
	}

	ret = hk_kprobe_remove(&r->u.kprobe);
	if (ret)
		return ret;

	/*
	 * the probe is gone, so no new call can be redirected, but a core that was
	 * already inside the replacement is still there and still owns an entry in the
	 * guard. the grace period is what it takes for that core to be out, the same
	 * wait hk_inline does before it frees a trampoline
	 */
	hk_wait_tasks_rcu();
	xa_destroy(&r->guard);
	return 0;
}
