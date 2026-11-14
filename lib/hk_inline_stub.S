// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

	.text
	.align	2
	.global	hk_inline_decide_stub
	.type	hk_inline_decide_stub, %function
/* frame 96: x0-x7 0 x8 64 lr 72 sp 80 ctx 88 */
hk_inline_decide_stub:
	.inst	0xd503245f		/* bti c */
	sub	sp, sp, #96
	stp	x0, x1, [sp]
	stp	x2, x3, [sp, #16]
	stp	x4, x5, [sp, #32]
	stp	x6, x7, [sp, #48]
	str	x8, [sp, #64]
	str	x30, [sp, #72]
	add	x9, sp, #96
	str	x9, [sp, #80]
	str	x17, [sp, #88]

	mov	x0, sp
	ldr	x1, [x17, #8]
	ldr	x9, [x17, #16]
	blr	x9
	mov	w10, w0
	cbnz	w10, 1f

	ldp	x0, x1, [sp]
	ldp	x2, x3, [sp, #16]
	ldp	x4, x5, [sp, #32]
	ldp	x6, x7, [sp, #48]
	ldr	x8, [sp, #64]
	ldr	x30, [sp, #72]
	ldr	x9, [sp, #88]
	ldr	x16, [x9]
	ldr	x9, [sp, #80]
	mov	sp, x9
	br	x16

1:
	ldr	x0, [sp]
	ldr	x30, [sp, #72]
	ldr	x9, [sp, #80]
	mov	sp, x9
	ret
	.size	hk_inline_decide_stub, . - hk_inline_decide_stub
