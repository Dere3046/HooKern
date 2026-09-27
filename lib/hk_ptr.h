// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMHOOK_HK_PTR_H
#define LKMHOOK_HK_PTR_H

#include <linux/types.h>

/*
 * swap the pointer at slot for replacement and record the original for
 * hk_ptr_unhook or hk_ptr_exit. one lock is held across the duplicate check, the
 * read, the swap and the record, so two hooks cannot interleave and lose an
 * original. the swap itself is a single aligned word store through the fixmap
 * alias, a core that reads the slot sees the old pointer or the new one
 *
 * the hooks live in a list, there is no fixed capacity and no -ENOSPC. the walk
 * over the live hooks costs the same as the old table scan. the tracking entry is
 * allocated, so this runs in process context, and -ENOMEM is the new full case
 *
 * -EINVAL on a NULL slot or replacement, -EEXIST when the slot is already hooked,
 * -EFAULT when the slot cannot be read, -EIO when the write fails
 */
int hk_ptr_hook(void **slot, void *replacement, void **orig_out);

/* restore the recorded original, silent when the slot is not hooked */
void hk_ptr_unhook(void **slot);

/* restore every tracked slot, called by hk_exit */
void hk_ptr_exit(void);

#endif
