// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/errno.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
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
#define HK_INS_BR_ANY 0xD61F0000
#define HK_INS_BR_MASK 0xFFFFFC1F
#define HK_INS_BRK_ANY 0xD4200000
#define HK_INS_BRK_MASK 0xFFE00000
#define HK_INS_MOV_MASK 0x7F800000
#define HK_INS_MOVZ 0x52800000
#define HK_INS_MOVK 0x72800000
#define HK_INS_MOV_X9_LR 0xAA1E03E9

/* dry run sink for the probe, the tables allow 8 words per instruction */
#define HK_PROBE_SCRATCH 128

/* serializes every install and restore, see the note at the lock site */
static DEFINE_MUTEX(g_inline_lock);

/*
 * one node per live hook window, under g_inline_lock. the window belongs to the
 * install and is handed back by hk_inline_disable or hk_inline_free, so a second
 * hook can take the address once the first entry is restored. the hook pointer
 * is the name of the node, a symbol the caller keeps alive while it is hooked
 */
struct hk_inline_own {
	struct list_head list;
	struct hk_inline *hook;
	unsigned long start;
	u32 len;
};

static LIST_HEAD(g_inline_owned);

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
	const u8 *src;		/* entry window copy, NULL reads tramp_start */
	unsigned long inst_addr;
	unsigned long tramp_start;
	unsigned long tramp_end;
	unsigned long backup_start;
};

static __nocfi hk_inst_type_t hk_insn_type(u32 insn)
{
	int i;

	for (i = 0; i < (int)ARRAY_SIZE(hk_masks); i++)
		if ((insn & hk_masks[i]) == hk_types[i])
			return (hk_inst_type_t)(i + 1);
	return HK_INST_IGNORE;
}

/* the tables are 0 based, the instruction types are not */
static int hk_insn_index(u32 insn)
{
	return (int)hk_insn_type(insn) - 1;
}

static bool hk_in_tramp(const struct hk_relo_ctx *c, u64 addr)
{
	return addr >= c->tramp_start && addr < c->tramp_end;
}

static u64 hk_relo_in_tramp(const struct hk_relo_ctx *c, u64 addr)
{
	const u8 *src = c->src ? c->src : (const u8 *)c->tramp_start;
	u64 fix = c->backup_start;
	u32 inst;
	u32 idx;
	int j;

	if (!hk_in_tramp(c, addr))
		return addr;
	idx = (addr - c->tramp_start) / 4;
	for (j = 0; j < (int)idx; j++) {
		inst = hk_get_insn(src + j * 4);
		fix += hk_relo_len[hk_insn_index(inst)] * 4;
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
	int i = hk_insn_index(insn);
	int ret = 0;

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

static __nocfi int hk_inline_apply(struct hk_inline *h, const char *sym,
				   const char *wrapper_sym,
				   unsigned long addr);

/* the entry address a hook on sym patches: the resolver result with the same
 * branch chain walked, so the collision window and the probe agree */
static __nocfi unsigned long hk_read_addr(const char *sym)
{
	unsigned long addr;

	addr = hk_resolve(sym);
	if (!addr)
		return 0;
	hk_resolve_branch_chain(addr, &addr);
	return addr;
}

/* the window of another live hook that overlaps [start, start + len), NULL when
 * the range is free. the caller holds g_inline_lock */
static const struct hk_inline_own *hk_inline_overlap(unsigned long start,
						     u32 len)
{
	const struct hk_inline_own *ent;
	unsigned long end = start + len;

	list_for_each_entry(ent, &g_inline_owned, list) {
		if (start < ent->start + ent->len && ent->start < end)
			return ent;
	}
	return NULL;
}

/* name both sides of the overlap, the caller holds g_inline_lock */
static void hk_inline_report(const char *what, const char *sym,
			     unsigned long start, u32 len,
			     const struct hk_inline_own *other)
{
	pr_warn("[lkmhook] %s %s window 0x%lx+%u collides with %s 0x%lx+%u\n",
		what, sym, start, len,
		other->hook->name ? other->hook->name : "?",
		other->start, other->len);
}

/*
 * claim [start, start + len) for h, -EBUSY when another live hook owns part of
 * it. a claim is taken before any text is read or written and a failed install
 * hands it back, so every claim has an owner that can release it
 */
static int hk_inline_own(struct hk_inline *h, const char *sym,
			 unsigned long start, u32 len)
{
	const struct hk_inline_own *other;
	struct hk_inline_own *own;
	struct hk_inline_own *ent;

	mutex_lock(&g_inline_lock);
	list_for_each_entry(ent, &g_inline_owned, list) {
		if (ent->hook != h)
			continue;
		pr_warn("[lkmhook] inline %s already installed\n", sym);
		mutex_unlock(&g_inline_lock);
		return -EBUSY;
	}
	other = hk_inline_overlap(start, len);
	if (other) {
		hk_inline_report("inline", sym, start, len, other);
		mutex_unlock(&g_inline_lock);
		return -EBUSY;
	}

	own = kzalloc(sizeof(*own), GFP_KERNEL);
	if (!own) {
		mutex_unlock(&g_inline_lock);
		return -ENOMEM;
	}
	own->hook = h;
	own->start = start;
	own->len = len;
	list_add(&own->list, &g_inline_owned);
	mutex_unlock(&g_inline_lock);
	return 0;
}

/* hand the window back so a later install can take it */
static void hk_inline_release(const struct hk_inline *h)
{
	struct hk_inline_own *ent;

	mutex_lock(&g_inline_lock);
	list_for_each_entry(ent, &g_inline_owned, list) {
		if (ent->hook != h)
			continue;
		list_del(&ent->list);
		mutex_unlock(&g_inline_lock);
		kfree(ent);
		return;
	}
	mutex_unlock(&g_inline_lock);
}

/* the probe half of the claim: name the live window that would refuse an install
 * on [start, start + len), 0 when the range is free */
static int hk_inline_collide(const char *sym, unsigned long start, u32 len,
			     unsigned long *out)
{
	const struct hk_inline_own *other;

	mutex_lock(&g_inline_lock);
	other = hk_inline_overlap(start, len);
	if (!other) {
		mutex_unlock(&g_inline_lock);
		return 0;
	}
	*out = other->start;
	hk_inline_report("probe", sym, start, len, other);
	mutex_unlock(&g_inline_lock);
	return -EBUSY;
}

__nocfi int hk_inline_hook(struct hk_inline *h, const char *sym,
			   const char *wrapper_sym)
{
	unsigned long addr;
	int ret;

	if (!h || !sym || !wrapper_sym)
		return -EINVAL;

	/*
	 * one lock across trampoline allocation, relocation and both text
	 * writes, so two installs cannot interleave their trampolines or their
	 * entry windows. the write itself is still a burst of instructions and
	 * a core that executes the target right now can see half of it, the
	 * lock only takes the second writer out of the picture
	 *
	 * stop_machine is not used around this path. only the last write could
	 * run from a callback, and a stop_machine callback must neither sleep
	 * nor allocate while this path allocates the trampoline and resolves
	 * symbols. the split has to come first: prepare under this lock, then
	 * commit the detour from a callback that does neither
	 */
	addr = hk_read_addr(sym);
	ret = hk_inline_own(h, sym, addr, HK_INLINE_PATCH_LEN);
	if (ret)
		return ret;
	mutex_lock(&g_inline_lock);
	ret = hk_inline_apply(h, sym, wrapper_sym, addr);
	mutex_unlock(&g_inline_lock);
	if (ret)
		hk_inline_release(h);
	return ret;
}

static __nocfi int hk_inline_apply(struct hk_inline *h, const char *sym,
				   const char *wrapper_sym, unsigned long addr)
{
	struct hk_relo_ctx ctx;
	u32 *tramp;
	u32 detour[HK_INLINE_ENTRY_MAX];
	unsigned long wrapper;
	unsigned long mem;
	u32 i;
	u32 insn;
	int ret;

	memset(h, 0, sizeof(*h));
	tramp = kzalloc(256, GFP_KERNEL);
	if (!tramp)
		return -ENOMEM;

	if (!addr) {
		pr_warn("[lkmhook] inline resolve %s failed\n", sym);
		return -ENODATA;
	}
	wrapper = hk_resolve(wrapper_sym);
	if (!wrapper) {
		pr_warn("[lkmhook] inline resolve %s failed\n", wrapper_sym);
		return -ENODATA;
	}
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
	h->addr = addr;
	h->window = HK_INLINE_PATCH_LEN;
	h->name = sym;

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
	ctx.tramp_end = addr + HK_INLINE_PATCH_LEN;
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
	ctx.inst_addr = addr + HK_INLINE_PATCH_LEN;
	ret = hk_relo_abs_jump(&ctx, addr + HK_INLINE_PATCH_LEN);
	if (ret)
		goto err_free;

	ret = hk_patch_text((void *)mem, tramp,
			     ctx.count * 4 + 24,
			     HK_PATCH_FLUSH_DCACHE | HK_PATCH_FLUSH_ICACHE);
	if (ret)
		goto err_free;

	h->orig = mem + 20;

	detour[0] = HK_INS_BTI_JC;
	detour[1] = HK_INS_LDR_X17;
	detour[2] = HK_INS_RET_X17;
	detour[3] = mem & 0xFFFFFFFF;
	detour[4] = mem >> 32;
	ret = hk_patch_text((void *)addr, detour, HK_INLINE_PATCH_LEN,
			    HK_PATCH_FLUSH_DCACHE | HK_PATCH_FLUSH_ICACHE);
	if (ret) {
		hk_patch_text((void *)addr, h->saved, HK_INLINE_PATCH_LEN,
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
	int ret = 0;

	/* the restore is a text write too, keep it off a concurrent install */
	mutex_lock(&g_inline_lock);
	if (!h || !h->addr) {
		mutex_unlock(&g_inline_lock);
		return -EINVAL;
	}
	if (h->disabled) {
		mutex_unlock(&g_inline_lock);
		return 0;
	}
	if (hk_patch_text((void *)h->addr, h->saved, HK_INLINE_PATCH_LEN,
			  HK_PATCH_FLUSH_DCACHE | HK_PATCH_FLUSH_ICACHE)) {
		mutex_unlock(&g_inline_lock);
		return -EIO;
	}
	h->disabled = true;
	mutex_unlock(&g_inline_lock);

	/* the entry is the caller's bytes again, the window is up for grabs */
	hk_inline_release(h);
	return 0;
}

void hk_inline_free(struct hk_inline *h)
{
	mutex_lock(&g_inline_lock);
	if (!h) {
		mutex_unlock(&g_inline_lock);
		return;
	}
	if (h->addr && !h->disabled) {
		mutex_unlock(&g_inline_lock);
		pr_warn("[lkmhook] inline free before disable\n");
		return;
	}
	if (h->mem)
		hk_exec_free(h->mem);
	h->addr = 0;
	h->orig = 0;
	h->mem = NULL;
	h->disabled = false;
	mutex_unlock(&g_inline_lock);

	/*
	 * hk_inline_disable already handed the window back, this is the release
	 * for a hook that never reached disable. the node keeps no bytes, the
	 * entry still carries the last detour, so a claim taken here covers
	 * bytes the caller has to restore itself
	 */
	hk_inline_release(h);
}

void hk_inline_unhook(struct hk_inline *h)
{
	if (!h)
		return;
	hk_inline_disable(h);
	hk_inline_free(h);
}

/* a resolver result can be stale and a b target is arithmetic, so the probe
 * never dereferences a target directly */
static __nocfi int hk_read_code(unsigned long addr, void *dst, size_t len)
{
	return copy_from_kernel_nofault(dst, (const void *)addr, len);
}

static __nocfi int hk_fetch_insn(unsigned long addr, u32 *out)
{
	u8 raw[4];

	if (hk_read_code(addr, raw, sizeof(raw)))
		return -EFAULT;
	*out = hk_get_insn(raw);
	return 0;
}

/* the same walk as hk_resolve_branch_chain, which reads the target directly.
 * a thunk is a supported hook target, here it is a report */
static __nocfi int hk_follow_branch(unsigned long addr, unsigned long *out)
{
	u32 insn;
	int depth;

	for (depth = 0; depth < 32; depth++) {
		if (hk_fetch_insn(addr, &insn))
			return -EFAULT;
		if (hk_is_b(insn)) {
			addr = hk_decode_b_target(insn, addr);
			continue;
		}
		if (!hk_is_hint(insn))
			break;
		if (hk_fetch_insn(addr + 4, &insn))
			return -EFAULT;
		if (!hk_is_b(insn))
			break;
		addr = hk_decode_b_target(insn, addr + 4);
	}
	*out = addr;
	return 0;
}

static __nocfi bool hk_is_br(u32 insn)
{
	return (insn & HK_INS_BR_MASK) == HK_INS_BR_ANY;
}

static __nocfi bool hk_is_brk(u32 insn)
{
	return (insn & HK_INS_BRK_MASK) == HK_INS_BRK_ANY;
}

/* hint space, wider than hk_is_hint: bti is outside that mask and the detour
 * this library writes leads with bti jc */
static __nocfi bool hk_is_pad(u32 insn)
{
	return (insn & 0xFFFFF01F) == 0xD503201F;
}

/* br carries its register in rn, the literal loads and the moves in rd */
static __nocfi u32 hk_stub_rn(u32 insn)
{
	return (insn >> 5) & 0x1F;
}

static __nocfi u32 hk_stub_rd(u32 insn)
{
	return insn & 0x1F;
}

/*
 * exact stubs only. the relocation tables leave br, brk, movz and movk out, so
 * they are spelled out here, and anything else has to stay plain: a stub that
 * passes for a prologue is the answer a caller cannot recover from
 */
static __nocfi enum hk_inline_state hk_stub_state(const u32 *win,
						  const char **reason)
{
	const u32 *s = win;
	int left = HK_INLINE_ENTRY_MAX;
	u32 rd;
	int i;

	/* the ftrace preamble, every instrumented entry carries it, and a live
	 * one is patched to a bl that a detour would sit on top of */
	if (win[0] == HK_INS_MOV_X9_LR) {
		*reason = hk_insn_type(win[1]) == HK_INST_BL ?
			  "ftrace call site at entry" : "ftrace patch site at entry";
		return HK_INLINE_PATCHSITE;
	}
	if (hk_is_pad(win[0])) {
		s++;
		left--;
	}
	rd = hk_stub_rd(s[0]);
	if (hk_is_br(s[0])) {
		*reason = "br at entry";
		return HK_INLINE_HOOKED;
	}
	if (hk_is_brk(s[0])) {
		*reason = "brk at entry";
		return HK_INLINE_HOOKED;
	}
	/* a b behind a pad the branch walk does not cross, bti is outside
	 * hk_is_hint, so the hook would patch this entry and not its target */
	if (hk_is_b(s[0])) {
		*reason = "direct b at entry";
		return HK_INLINE_BRANCHED;
	}
	if (hk_insn_type(s[0]) == HK_INST_LDR_64 && hk_is_br(s[1]) &&
	    hk_stub_rn(s[1]) == rd) {
		*reason = "ldr br stub at entry";
		return HK_INLINE_HOOKED;
	}
	if ((s[0] & HK_INS_MOV_MASK) == HK_INS_MOVZ) {
		for (i = 1; i < left; i++) {
			if (hk_is_br(s[i]) && hk_stub_rn(s[i]) == rd) {
				*reason = "movz br stub at entry";
				return HK_INLINE_HOOKED;
			}
			if ((s[i] & HK_INS_MOV_MASK) != HK_INS_MOVK ||
			    hk_stub_rd(s[i]) != rd)
				break;
		}
	}
	return HK_INLINE_PLAIN;
}

__nocfi int hk_inline_probe(const char *sym, struct hk_inline_probe *out)
{
	struct hk_relo_ctx ctx;
	u8 raw[HK_INLINE_PATCH_LEN];
	u32 win[HK_INLINE_ENTRY_MAX];
	u32 scratch[HK_PROBE_SCRATCH];
	unsigned long addr;
	unsigned long target;
	u32 i;
	int ret;

	if (!sym || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	out->patch_len = HK_INLINE_PATCH_LEN;
	out->state = HK_INLINE_UNRESOLVED;
	out->reason = "symbol not resolved";

	addr = hk_resolve(sym);
	if (!addr)
		return 0;
	if (!hk_ker_addr_ok(addr)) {
		out->state = HK_INLINE_UNSUPPORTED;
		out->reason = "not a kernel address";
		return 0;
	}
	out->addr = addr;

	if (hk_follow_branch(addr, &target)) {
		out->state = HK_INLINE_UNREADABLE;
		out->reason = "entry not readable";
		return 0;
	}
	if (!hk_ker_addr_ok(target)) {
		out->state = HK_INLINE_UNSUPPORTED;
		out->reason = "not a kernel address";
		return 0;
	}
	out->target = target;

	/* the entry is not judged further, an install onto it is refused */
	if (hk_inline_collide(sym, target, HK_INLINE_PATCH_LEN,
			      &out->collide_addr)) {
		out->state = HK_INLINE_COLLISION;
		out->reason = "window owned by a live hook";
		return 0;
	}

	if (hk_read_code(target, raw, sizeof(raw))) {
		out->state = HK_INLINE_UNREADABLE;
		out->reason = "entry not readable";
		return 0;
	}
	for (i = 0; i < HK_INLINE_ENTRY_MAX; i++)
		win[i] = hk_get_insn(raw + i * 4);

	out->state = hk_stub_state(win, &out->reason);
	if (out->state != HK_INLINE_PLAIN)
		return 0;

	/* dry run the relocator over the copy, scratch is never patched and
	 * never mapped executable, only the refusal is of interest */
	memset(&ctx, 0, sizeof(ctx));
	ctx.dst = scratch;
	ctx.src = raw;
	ctx.tramp_start = target;
	ctx.tramp_end = target + HK_INLINE_PATCH_LEN;
	for (i = 0; i < HK_INLINE_ENTRY_MAX; i++) {
		ctx.inst_addr = target + i * 4;
		ret = hk_relo_inst(&ctx, win[i]);
		if (ret) {
			out->state = HK_INLINE_UNSUPPORTED;
			out->reason = "entry operand points into the patched window";
			return 0;
		}
	}

	if (target != addr) {
		out->state = HK_INLINE_BRANCHED;
		out->reason = "direct b at entry";
		return 0;
	}
	out->state = HK_INLINE_PLAIN;
	out->reason = "no branch stub found";
	return 0;
}
