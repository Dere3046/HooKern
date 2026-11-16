// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#ifndef LKMHOOK_HK_INSN_H
#define LKMHOOK_HK_INSN_H

#include <linux/types.h>

#define HK_INSN_B_MASK			0xFC000000u
#define HK_INSN_B_VAL			0x14000000u

#define HK_INSN_BL_MASK			0xFC000000u
#define HK_INSN_BL_VAL			0x94000000u

#define HK_INSN_RET_MASK		0xFFFFFC1Fu
#define HK_INSN_RET_VAL			0xD65F0000u
#define HK_INSN_RET			0xD65F03C0u

#define HK_INSN_RET_AUTH_MASK		0xFFFFFBFFu
#define HK_INSN_RET_AUTH_VAL		0xD65F0BFFu
#define HK_INSN_RETAA			0xD65F0BFFu
#define HK_INSN_RETAB			0xD65F0FFFu

#define HK_INSN_BCOND_MASK		0xFF000010u
#define HK_INSN_BCOND_VAL		0x54000000u

#define HK_INSN_CBZ_MASK		0x7F000000u
#define HK_INSN_CBZ_VAL			0x34000000u

#define HK_INSN_CBNZ_MASK		0x7F000000u
#define HK_INSN_CBNZ_VAL		0x35000000u

#define HK_INSN_TBZ_MASK		0x7F000000u
#define HK_INSN_TBZ_VAL			0x36000000u

#define HK_INSN_TBNZ_MASK		0x7F000000u
#define HK_INSN_TBNZ_VAL		0x37000000u

#define HK_INSN_LDR_LIT_X16_MASK	0xFF00001Fu
#define HK_INSN_LDR_LIT_X16_VAL		0x58000010u

#define HK_INSN_BR_X16			0xD61F0200u
#define HK_INSN_NOP			0xD503201Fu

#define HK_INSN_STP_FP_LR_PRE_MASK	0xFFC0FFFFu
#define HK_INSN_STP_FP_LR_PRE_VAL	0xA9807BFDu

#define HK_INSN_STP_FP_LR_OFF_MASK	0xFFC0FFFFu
#define HK_INSN_STP_FP_LR_OFF_VAL	0xA9007BFDu

static inline bool hk_insn_is_b(u32 insn)
{
	return (insn & HK_INSN_B_MASK) == HK_INSN_B_VAL;
}

static inline bool hk_insn_is_bl(u32 insn)
{
	return (insn & HK_INSN_BL_MASK) == HK_INSN_BL_VAL;
}

static inline bool hk_insn_is_ret(u32 insn)
{
	return (insn & HK_INSN_RET_MASK) == HK_INSN_RET_VAL ||
	       (insn & HK_INSN_RET_AUTH_MASK) == HK_INSN_RET_AUTH_VAL;
}

static inline bool hk_insn_is_bcond(u32 insn)
{
	return (insn & HK_INSN_BCOND_MASK) == HK_INSN_BCOND_VAL;
}

static inline bool hk_insn_is_cbz(u32 insn)
{
	return (insn & HK_INSN_CBZ_MASK) == HK_INSN_CBZ_VAL;
}

static inline bool hk_insn_is_cbnz(u32 insn)
{
	return (insn & HK_INSN_CBNZ_MASK) == HK_INSN_CBNZ_VAL;
}

static inline bool hk_insn_is_tbz(u32 insn)
{
	return (insn & HK_INSN_TBZ_MASK) == HK_INSN_TBZ_VAL;
}

static inline bool hk_insn_is_tbnz(u32 insn)
{
	return (insn & HK_INSN_TBNZ_MASK) == HK_INSN_TBNZ_VAL;
}

static inline bool hk_insn_is_nop(u32 insn)
{
	return insn == HK_INSN_NOP;
}

static inline bool hk_insn_is_stp_fp_lr(u32 insn)
{
	return (insn & HK_INSN_STP_FP_LR_PRE_MASK) == HK_INSN_STP_FP_LR_PRE_VAL ||
	       (insn & HK_INSN_STP_FP_LR_OFF_MASK) == HK_INSN_STP_FP_LR_OFF_VAL;
}

static inline s64 hk_insn_decode_imm26(u32 insn)
{
	s32 imm26;

	imm26 = (s32)(insn & 0x03FFFFFF);
	if (imm26 & 0x02000000) {
		imm26 |= ~0x03FFFFFF;
	}
	return (s64)imm26 * 4;
}

static inline s64 hk_insn_decode_imm19(u32 insn)
{
	s32 imm19;

	imm19 = (s32)((insn >> 5) & 0x7FFFF);
	if (imm19 & 0x40000) {
		imm19 |= ~0x7FFFF;
	}
	return (s64)imm19 * 4;
}

static inline s64 hk_insn_decode_imm14(u32 insn)
{
	s32 imm14;

	imm14 = (s32)((insn >> 5) & 0x3FFF);
	if (imm14 & 0x2000) {
		imm14 |= ~0x3FFF;
	}
	return (s64)imm14 * 4;
}

#endif
