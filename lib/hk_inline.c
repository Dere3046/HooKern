// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "hk.h"
#include "hk_patch.h"
#include "hk_inline.h"

#define HK_TRAMP_HEAD (4 + HK_INLINE_WINDOW_MAX + HK_INLINE_WINDOW_MIN)

static __nocfi u32 hk_get_insn(const u8 *p)
{
	return le32_to_cpu(*(const u32 *)p);
}

static __nocfi long hk_sext(u32 v, int bits)
{
	return (long)((s64)(s32)(v << (32 - bits)) >> (32 - bits));
}

static __nocfi bool hk_insn_ok(u32 insn, u32 off, u32 window)
{
	u32 top = insn >> 24;
	long disp, target;

	if ((insn & 0xFC000000) == 0x14000000) {
		disp = hk_sext(insn & 0x03FFFFFF, 26) << 2;
		target = off + 4 + disp;
		return target >= 0 && target < (long)window;
	}
	if ((insn & 0xFF000010) == 0x54000000) {
		disp = hk_sext((insn >> 5) & 0x7FFFF, 19) << 2;
		target = off + 4 + disp;
		return target >= 0 && target < (long)window;
	}
	if ((insn & 0x7F000000) == 0x34000000) {
		disp = hk_sext((insn >> 5) & 0x7FFFF, 19) << 2;
		target = off + 4 + disp;
		return target >= 0 && target < (long)window;
	}
	if ((insn & 0x7E000000) == 0x36000000) {
		disp = hk_sext((insn >> 5) & 0x3FFF, 14) << 2;
		target = off + 4 + disp;
		return target >= 0 && target < (long)window;
	}
	if ((insn & 0x1F000000) == 0x10000000)
		return false;
	if (top == 0x18 || top == 0x58 || top == 0xD8)
		return false;
	return true;
}

static __nocfi u32 hk_enc_movz(u32 rd, u32 imm, u32 hw)
{
	return 0xD2800000 | (hw << 21) | ((imm & 0xFFFF) << 5) | rd;
}

static __nocfi u32 hk_enc_movk(u32 rd, u32 imm, u32 hw)
{
	return 0xF2800000 | (hw << 21) | ((imm & 0xFFFF) << 5) | rd;
}

static __nocfi u32 hk_enc_br(u32 rn)
{
	return 0xD61F0000 | (rn << 5);
}

static __nocfi void hk_build_jump(u32 *out, unsigned long target)
{
	out[0] = hk_enc_movz(16, target & 0xFFFF, 0);
	out[1] = hk_enc_movk(16, (target >> 16) & 0xFFFF, 1);
	out[2] = hk_enc_movk(16, (target >> 32) & 0xFFFF, 2);
	out[3] = hk_enc_movk(16, (target >> 48) & 0xFFFF, 3);
	out[4] = hk_enc_br(16);
}

int hk_inline_hook(struct hk_inline *h, const char *sym, void *stub,
		   unsigned long wrapper)
{
	u8 buf[HK_INLINE_WINDOW_MAX];
	u32 tramp[HK_TRAMP_HEAD / 4];
	u32 detour[HK_INLINE_WINDOW_MIN / 4];
	unsigned long addr;
	u32 window = 0, w, i;
	int ret;

	if (!h || !sym || !stub || !wrapper)
		return -EINVAL;
	memset(h, 0, sizeof(*h));

	addr = hk_resolve(sym);
	if (!addr) {
		pr_warn("[lkmhook] inline resolve %s failed\n", sym);
		return -ENODATA;
	}
	if (copy_from_kernel_nofault(buf, (void *)addr, sizeof(buf))) {
		pr_warn("[lkmhook] inline read %s failed\n", sym);
		return -EFAULT;
	}

	if (hk_patch_guarded((void *)addr) || hk_patch_guarded(stub)) {
		/*
		 * guarded pages (BTI): the trampoline jump back targets
		 * plain function body without a bti landing pad, indirect
		 * branches to it fault. refuse instead of crashing.
		 */
		pr_warn("[lkmhook] inline %s on BTI kernel unsupported\n",
			sym);
		return -EOPNOTSUPP;
	}

	for (w = HK_INLINE_WINDOW_MIN; w <= HK_INLINE_WINDOW_MAX; w += 4) {
		bool ok = true;

		for (i = 0; i < w; i += 4) {
			if (!hk_insn_ok(hk_get_insn(buf + i), i, w)) {
				ok = false;
				break;
			}
		}
		if (ok) {
			window = w;
			break;
		}
	}
	if (!window) {
		pr_warn("[lkmhook] inline %s prologue not relocatable\n", sym);
		return -ENOEXEC;
	}

	/* trampoline: bti + window + jump(func+window) */
	tramp[0] = 0xD503245F;
	for (i = 0; i < window / 4; i++)
		tramp[1 + i] = hk_get_insn(buf + i * 4);
	hk_build_jump(tramp + 1 + window / 4, addr + window);
	ret = hk_patch_text(stub, tramp, 4 + window + HK_INLINE_WINDOW_MIN,
			    HK_PATCH_FLUSH_DCACHE | HK_PATCH_FLUSH_ICACHE);
	if (ret) {
		pr_warn("[lkmhook] inline tramp %s failed %d\n", sym, ret);
		return ret;
	}

	memcpy(h->saved, buf, HK_INLINE_WINDOW_MIN);
	hk_build_jump(detour, wrapper);
	ret = hk_patch_text((void *)addr, detour, HK_INLINE_WINDOW_MIN,
			    HK_PATCH_FLUSH_DCACHE | HK_PATCH_FLUSH_ICACHE);
	if (ret) {
		pr_warn("[lkmhook] inline detour %s failed %d\n", sym, ret);
		return ret;
	}

	h->name = sym;
	h->addr = addr;
	h->window = window;
	h->stub = stub;
	pr_info("[lkmhook] inline %s @ 0x%lx window=%u tramp=%px\n",
		sym, addr, window, stub);
	return 0;
}

void hk_inline_unhook(struct hk_inline *h)
{
	if (!h->addr)
		return;
	hk_patch_text((void *)h->addr, h->saved, HK_INLINE_WINDOW_MIN,
		      HK_PATCH_FLUSH_DCACHE | HK_PATCH_FLUSH_ICACHE);
	h->addr = 0;
}
