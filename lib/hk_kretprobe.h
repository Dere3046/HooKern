// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMHOOK_HK_KRETPROBE_H
#define LKMHOOK_HK_KRETPROBE_H

#include <linux/kprobes.h>
#include <linux/types.h>

struct hk_kretprobe {
	struct kretprobe rp;
};

/*
 * a kretprobe fires after the target returns, the return value is in x0 and a
 * store to regs through hk_regs_set_ret rewrites it, which a kprobe cannot do
 * the handler runs on the returning core with the registers of the caller, so
 * the call has already happened and cannot be suppressed. use the entry and
 * return pair when the handler needs per call state, the entry handler returns
 * 1 to accept the instance and fills ri->data with data_size bytes
 *
 * the address gates are the kprobe ones, register_kretprobe registers a kprobe
 * first, so hk_kprobe_check answers for a kretprobe target too and a refused
 * install logs the symbol and the gate. installs are tracked in a list and
 * removed again by hk_kretprobe_exit, there is no ceiling and no -ENOSPC,
 * -ENOMEM when the tracking node cannot be allocated and nothing is registered
 *
 * the target has to return. a function that never returns leaks one instance
 * per call until maxactive runs out, and the probe then misses returns instead
 * of failing the install. a hot target other cores execute during
 * installation still belongs here, never to hk_inline_hook
 */
int hk_kretprobe_install(struct hk_kretprobe *h, const char *sym,
			 kretprobe_handler_t handler);
int hk_kretprobe_install_ex(struct hk_kretprobe *h, const char *sym,
			    kretprobe_handler_t entry,
			    kretprobe_handler_t handler,
			    size_t data_size);
/* unregister and drop the tracking node, a second remove is a no op */
void hk_kretprobe_remove(struct hk_kretprobe *h);
/* unregister every tracked probe, called by hk_exit */
void hk_kretprobe_exit(void);

#endif
