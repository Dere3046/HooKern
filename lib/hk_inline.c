// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>

#include "hk.h"
#include "hk_patch.h"
#include "hk_inline.h"

#define HK_TRAMP_SIZE 4096
#define HK_TRAMP_MAX 64
#define HK_INS_LDR_X17 0x58000051
#define HK_INS_BR_X17 0xD61F0220
#define HK_INS_RET_X17 0xD65F0220
#define HK_INS_BLR_X17 0xD63F0220
#define HK_INS_NOP 0xD503201F
#define HK_INS_BTI_JC 0xD50324DF

typedef enum {
	HK_INST_B = 1,
	HK_INST_BC,
	HK_INST_BL,
	HK_INST_ADR,
	HK_INST_ADRP,
	HK_INST_LDR_32,
	HK_INST_LDR_64,
	HK_INST_LDRSW,
	HK_INST_PRFM,
	HK_INST_LDR_SIMD_32,
	HK_INST_LDR_SIMD_64,
	HK_INST_LDR_SIMD_128,
	HK_INST_CBZ,
	HK_INST_CBNZ,
	HK_INST_TBZ,
	HK_INST_TBNZ,
	HK_INST_IGNORE,
} hk_inst_type_t;

static const u32 hk_masks[] = {
	0xFC000000, 0xFF000010, 0xFC000000, 0x9F000000, 0x9F000000,
	0xFF000000, 0xFF000000, 0xFF000000, 0xFF000000,
	0xFF000000, 0xFF000000, 0xFF000000,
	0x7F000000, 0x7F000000, 0x7F000000, 0x7F000000,
	0x00000000,
};

static const u32 hk_types[] = {
	0x14000000, 0x54000000, 0x94000000, 0x10000000, 0x90000000,
	0x18000000, 0x58000000, 0x98000000, 0xD8000000,
	0x1C000000, 0x5C000000, 0x9C000000,
	0x34000000, 0x35000000, 0x36000000, 0x37000000,
	0x00000000,
};

static const int hk_relo_len[] = {
	6, 8, 6, 4, 4, 5, 5, 5, 7, 7, 7, 7, 6, 6, 6, 6, 2,
};

static __nocfi u32 hk_get_insn(const u8 *p)
{
	return le32_to_cpu(*(const u32 *)p);
}

static __nocfi long hk_sext(u64 v, int bits)
{
	if (bits < 64 && (v & (1ULL << (bits - 1))))
		v |= ~0ULL << bits;
	return (long)v;
}

static __nocfi u32 hk_enc_movz(u32 rd, u32 imm, u32 hw)
{
	return 0xD2800000 | (hw << 21) | ((imm & 0xFFFF) << 5) | rd;
}

static __nocfi u32 hk_enc_movk(u32 rd, u32 imm, u32 hw)
{
	return 0xF2800000 | (hw << 21) | ((imm & 0xFFFF) << 5) | rd;
}

static __nocfi void hk_build_jump(u32 *out, unsigned long target)
{
	out[0] = hk_enc_movz(16, target & 0xFFFF, 0);
	out[1] = hk_enc_movk(16, (target >> 16) & 0xFFFF, 1);
	out[2] = hk_enc_movk(16, (target >> 32) & 0xFFFF, 2);
	out[3] = hk_enc_movk(16, (target >> 48) & 0xFFFF, 3);
	out[4] = HK_INS_RET_X17;
}

static bool hk_is_b(u32 insn)
{
	return (insn & hk_masks[0]) == hk_types[0];
}

static bool hk_is_hint(u32 insn)
{
	return (insn & 0xFFFFFC1F) == 0xD503201F;
}

static u64 hk_decode_b_target(u32 insn, u64 pc)
{
	return pc + hk_sext(insn & 0x03FFFFFF, 26) * 4;
}

static u64 hk_resolve_branch_once(u64 addr)
{
	u32 inst;
	u32 n;
	u64 next;

	inst = hk_get_insn((const u8 *)addr);
	if (hk_is_b(inst))
		return hk_decode_b_target(inst, addr);
	if (hk_is_hint(inst)) {
		next = addr + 4;
		n = hk_get_insn((const u8 *)next);

		if (hk_is_b(n))
			return hk_decode_b_target(n, next);
	}
	return addr;
}

static int hk_resolve_branch_chain(unsigned long addr, unsigned long *out)
{
	int depth;

	for (depth = 0; depth < 32; depth++) {
		unsigned long target = hk_resolve_branch_once(addr);

		if (target == addr)
			break;
		addr = target;
	}
	*out = addr;
	return 0;
}

struct hk_relo_ctx {
	u32 *dst;
	u32 count;
	unsigned long inst_addr;
	unsigned long tramp_start;
	unsigned long tramp_end;
	unsigned long backup_start;
};

static bool hk_in_tramp(const struct hk_relo_ctx *c, u64 addr)
{
	return addr >= c->tramp_start && addr < c->tramp_end;
}

static u64 hk_relo_in_tramp(const struct hk_relo_ctx *c, u64 addr)
{
	u64 fix = c->backup_start;
	u32 inst;
	u32 idx;
	int j;
	int k;

	if (!hk_in_tramp(c, addr))
		return addr;
	idx = (addr - c->tramp_start) / 4;
	for (j = 0; j < (int)idx; j++) {
		inst = hk_get_insn((const u8 *)(c->tramp_start + j * 4));

		for (k = 0; k < (int)ARRAY_SIZE(hk_masks); k++)
			if ((inst & hk_masks[k]) == hk_types[k]) {
				fix += hk_relo_len[k] * 4;
				break;
			}
	}
	return fix;
}

static int hk_relo_abs_jump(struct hk_relo_ctx *c, u64 target)
{
	c->dst[c->count++] = HK_INS_LDR_X17;
	c->dst[c->count++] = HK_INS_RET_X17;
	c->dst[c->count++] = target & 0xFFFFFFFF;
	c->dst[c->count++] = target >> 32;
	return 0;
}

static int hk_relo_b(struct hk_relo_ctx *c, u32 insn, hk_inst_type_t type)
{
	u64 disp;
	u64 addr;

	if (type == HK_INST_BC)
		disp = hk_sext((insn >> 5) & 0x7FFFF, 19) << 2;
	else
		disp = hk_sext(insn & 0x03FFFFFF, 26) << 2;
	addr = c->inst_addr + disp;
	addr = hk_relo_in_tramp(c, addr);

	if (type == HK_INST_BC) {
		c->dst[c->count++] = (insn & 0xFF00001F) | 0x40;
		c->dst[c->count++] = 0x14000006;
	}
	c->dst[c->count++] = HK_INS_LDR_X17;
	c->dst[c->count++] = 0x14000003;
	c->dst[c->count++] = addr & 0xFFFFFFFF;
	c->dst[c->count++] = addr >> 32;
	if (type == HK_INST_BL)
		c->dst[c->count++] = HK_INS_BLR_X17;
	else
		c->dst[c->count++] = HK_INS_RET_X17;
	c->dst[c->count++] = HK_INS_NOP;
	return 0;
}

static int hk_relo_adr(struct hk_relo_ctx *c, u32 insn, hk_inst_type_t type)
{
	u32 xd = insn & 0x1F;
	u64 addr;

	if (type == HK_INST_ADR)
		addr = c->inst_addr + hk_sext(((insn >> 5) & 0x7FFFF) |
					      ((insn >> 29) & 0x3), 21);
	else {
		addr = (c->inst_addr & ~0xFFFUL) +
		       hk_sext(((insn >> 5) & 0x7FFFF) << 14 |
			       ((insn >> 29) & 0x3) << 12, 33);
		if (hk_in_tramp(c, addr))
			return -EOPNOTSUPP;
	}
	c->dst[c->count++] = 0x58000040 | xd;
	c->dst[c->count++] = 0x14000003;
	c->dst[c->count++] = addr & 0xFFFFFFFF;
	c->dst[c->count++] = addr >> 32;
	return 0;
}

static int hk_relo_ldr(struct hk_relo_ctx *c, u32 insn, hk_inst_type_t type)
{
	u32 rt = insn & 0x1F;
	u64 addr = c->inst_addr + hk_sext((insn >> 5) & 0x7FFFF, 19) * 4;

	if (hk_in_tramp(c, addr) && type != HK_INST_PRFM)
		return -EOPNOTSUPP;
	addr = hk_relo_in_tramp(c, addr);

	if (type == HK_INST_LDR_32 || type == HK_INST_LDR_64 ||
	    type == HK_INST_LDRSW) {
		u32 op;

		if (type == HK_INST_LDR_32)
			op = 0xB9400000;
		else if (type == HK_INST_LDR_64)
			op = 0xF9400000;
		else
			op = 0xB9800000;
		c->dst[c->count++] = 0x58000060 | rt;
		c->dst[c->count++] = op | rt | (rt << 5);
		c->dst[c->count++] = 0x14000003;
		c->dst[c->count++] = addr & 0xFFFFFFFF;
		c->dst[c->count++] = addr >> 32;
	} else {
		u32 op;

		if (type == HK_INST_PRFM)
			op = 0xF9800220;
		else if (type == HK_INST_LDR_SIMD_32)
			op = 0xBD400220;
		else if (type == HK_INST_LDR_SIMD_64)
			op = 0xFD400220;
		else
			op = 0x3DC00220;
		c->dst[c->count++] = 0xA93F47F0;
		c->dst[c->count++] = 0x58000091;
		c->dst[c->count++] = op | rt;
		c->dst[c->count++] = 0xF85F83F1;
		c->dst[c->count++] = 0x14000003;
		c->dst[c->count++] = addr & 0xFFFFFFFF;
		c->dst[c->count++] = addr >> 32;
	}
	return 0;
}

static int hk_relo_cb(struct hk_relo_ctx *c, u32 insn)
{
	u64 addr = c->inst_addr + hk_sext((insn >> 5) & 0x7FFFF, 19) * 4;

	addr = hk_relo_in_tramp(c, addr);
	c->dst[c->count++] = (insn & 0xFF00001F) | 0x40;
	c->dst[c->count++] = 0x14000005;
	c->dst[c->count++] = HK_INS_LDR_X17;
	c->dst[c->count++] = HK_INS_RET_X17;
	c->dst[c->count++] = addr & 0xFFFFFFFF;
	c->dst[c->count++] = addr >> 32;
	return 0;
}

static int hk_relo_tb(struct hk_relo_ctx *c, u32 insn)
{
	u64 addr = c->inst_addr + hk_sext((insn >> 5) & 0x3FFF, 14) * 4;

	addr = hk_relo_in_tramp(c, addr);
	c->dst[c->count++] = (insn & 0xFFF8001F) | 0x40;
	c->dst[c->count++] = 0x14000005;
	c->dst[c->count++] = HK_INS_LDR_X17;
	c->dst[c->count++] = HK_INS_RET_X17;
	c->dst[c->count++] = addr & 0xFFFFFFFF;
	c->dst[c->count++] = addr >> 32;
	return 0;
}

static int hk_relo_inst(struct hk_relo_ctx *c, u32 insn)
{
	int i;
	int ret = 0;

	for (i = 0; i < (int)ARRAY_SIZE(hk_masks); i++)
		if ((insn & hk_masks[i]) == hk_types[i])
			break;
	if (i == ARRAY_SIZE(hk_masks))
		i = ARRAY_SIZE(hk_masks) - 1;

	switch (i) {
	case 0:
	case 1:
	case 2:
		ret = hk_relo_b(c, insn, i + 1);
		break;
	case 3:
	case 4:
		ret = hk_relo_adr(c, insn, i == 3 ? HK_INST_ADR : HK_INST_ADRP);
		break;
	case 5:
	case 6:
	case 7:
	case 8:
	case 9:
	case 10:
	case 11:
		ret = hk_relo_ldr(c, insn, i + 1);
		break;
	case 12:
	case 13:
		ret = hk_relo_cb(c, insn);
		break;
	case 14:
	case 15:
		ret = hk_relo_tb(c, insn);
		break;
	default:
		c->dst[c->count++] = insn;
		c->dst[c->count++] = HK_INS_NOP;
		break;
	}
	return ret;
}

typedef void *(*hk_vmalloc_node_range_fn)(unsigned long size,
					  unsigned long align,
					  unsigned long start,
					  unsigned long end,
					  gfp_t gfp_mask,
					  pgprot_t prot,
					  unsigned long vm_flags,
					  int node,
					  const void *caller);

static __nocfi noinline void *hk_exec_alloc(unsigned long size)
{
	hk_vmalloc_node_range_fn fn;
	const char *name = "__vmalloc_node_range";

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
	name = "__vmalloc_node_range_noprof";
#endif
	fn = (hk_vmalloc_node_range_fn)hk_resolve(name);
	if (!fn || !hk_ker_addr_ok((unsigned long)fn))
		return NULL;
	return fn(size, 1, VMALLOC_START, VMALLOC_END,
		  GFP_KERNEL | __GFP_NOWARN, PAGE_KERNEL_EXEC,
		  VM_FLUSH_RESET_PERMS, NUMA_NO_NODE,
		  __builtin_return_address(0));
}

static __nocfi noinline void hk_exec_free(void *mem)
{
	vfree(mem);
}

__nocfi int hk_inline_hook(struct hk_inline *h, const char *sym,
		   const char *wrapper_sym)
{
	struct hk_relo_ctx ctx;
	u32 *tramp;
	u32 detour[5];
	unsigned long addr;
	unsigned long wrapper;
	unsigned long mem;
	u32 i;
	u32 insn;
	int ret;

	if (!h || !sym || !wrapper_sym)
		return -EINVAL;
	memset(h, 0, sizeof(*h));
	tramp = kzalloc(256, GFP_KERNEL);
	if (!tramp)
		return -ENOMEM;

	addr = hk_resolve(sym);
	if (!addr) {
		pr_warn("[lkmhook] inline resolve %s failed\n", sym);
		return -ENODATA;
	}
	wrapper = hk_resolve(wrapper_sym);
	if (!wrapper) {
		pr_warn("[lkmhook] inline resolve %s failed\n", wrapper_sym);
		return -ENODATA;
	}
	hk_resolve_branch_chain(addr, &addr);
	pr_info("[lkmhook] P1 addr=0x%lx\n", addr);
	if (!hk_ker_addr_ok(addr))
		return -EINVAL;

	mem = (unsigned long)hk_exec_alloc(HK_TRAMP_SIZE);
	if (!mem) {
		pr_warn("[lkmhook] inline exec alloc %s failed\n", sym);
		return -ENOMEM;
	}
	h->mem = (void *)mem;
	h->mem_size = HK_TRAMP_SIZE;

	tramp[0] = HK_INS_BTI_JC;
	tramp[1] = HK_INS_LDR_X17;
	tramp[2] = HK_INS_RET_X17;
	tramp[3] = wrapper & 0xFFFFFFFF;
	tramp[4] = wrapper >> 32;
	tramp[5] = HK_INS_BTI_JC;
	pr_info("[lkmhook] P2 mem=0x%lx wrapper=0x%lx\n", mem, wrapper);

	memset(&ctx, 0, sizeof(ctx));
	ctx.dst = tramp + 6;
	ctx.tramp_start = addr;
	ctx.tramp_end = addr + HK_INLINE_ENTRY_MAX * 4;
	ctx.backup_start = mem + 24;

	for (i = 0; i < HK_INLINE_ENTRY_MAX; i++) {
		insn = hk_get_insn((const u8 *)(addr + i * 4));

		h->saved[i * 4] = insn & 0xFF;
		h->saved[i * 4 + 1] = (insn >> 8) & 0xFF;
		h->saved[i * 4 + 2] = (insn >> 16) & 0xFF;
		h->saved[i * 4 + 3] = (insn >> 24) & 0xFF;
		ctx.inst_addr = addr + i * 4;
		ret = hk_relo_inst(&ctx, insn);
		if (ret)
			goto err_free;
	}
	pr_info("[lkmhook] P3 count=%u\n", ctx.count);
	ctx.inst_addr = addr + HK_INLINE_ENTRY_MAX * 4;
	ret = hk_relo_abs_jump(&ctx, addr + HK_INLINE_ENTRY_MAX * 4);
	if (ret)
		goto err_free;

	ret = hk_patch_text((void *)mem, tramp,
			     ctx.count * 4 + 24,
			     HK_PATCH_FLUSH_DCACHE | HK_PATCH_FLUSH_ICACHE);
	if (ret)
		goto err_free;

	h->orig = mem + 20;
	h->addr = addr;
	h->window = HK_INLINE_ENTRY_MAX * 4;
	h->name = sym;

	detour[0] = HK_INS_BTI_JC;
	detour[1] = HK_INS_LDR_X17;
	detour[2] = HK_INS_RET_X17;
	detour[3] = mem & 0xFFFFFFFF;
	detour[4] = mem >> 32;
	ret = hk_patch_text((void *)addr, detour, 20,
			    HK_PATCH_FLUSH_DCACHE | HK_PATCH_FLUSH_ICACHE);
	if (ret) {
		hk_patch_text((void *)addr, h->saved, 20,
			      HK_PATCH_FLUSH_DCACHE | HK_PATCH_FLUSH_ICACHE);
		goto err_free;
	}

	kfree(tramp);
	return 0;

err_free:
	kfree(tramp);
	hk_exec_free(h->mem);
	h->mem = NULL;
	pr_warn("[lkmhook] inline %s failed %d\n", sym, ret);
	return ret;
}

int hk_inline_disable(struct hk_inline *h)
{
	if (!h || !h->addr)
		return -EINVAL;
	if (h->disabled)
		return 0;
	hk_patch_text((void *)h->addr, h->saved, 20,
		      HK_PATCH_FLUSH_DCACHE | HK_PATCH_FLUSH_ICACHE);
	h->disabled = true;
	return 0;
}

void hk_inline_free(struct hk_inline *h)
{
	if (!h)
		return;
	if (h->addr && !h->disabled) {
		pr_warn("[lkmhook] inline free before disable\n");
		return;
	}
	if (h->mem)
		hk_exec_free(h->mem);
	h->addr = 0;
	h->orig = 0;
	h->mem = NULL;
	h->disabled = false;
}

void hk_inline_unhook(struct hk_inline *h)
{
	if (!h)
		return;
	hk_inline_disable(h);
	hk_inline_free(h);
}
