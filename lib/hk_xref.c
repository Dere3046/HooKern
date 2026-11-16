// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>

#include "hk.h"
#include "hk_insn.h"
#include "hk_xref.h"

static inline unsigned long decode_forward_branch(u32 insn, unsigned long pc)
{
	s64 off;

	if (hk_insn_is_bcond(insn) || hk_insn_is_cbz(insn) ||
	    hk_insn_is_cbnz(insn)) {
		off = hk_insn_decode_imm19(insn);
		if (off > 0) {
			return (unsigned long)((s64)pc + off);
		}
	}
	if (hk_insn_is_tbz(insn) || hk_insn_is_tbnz(insn)) {
		off = hk_insn_decode_imm14(insn);
		if (off > 0) {
			return (unsigned long)((s64)pc + off);
		}
	}
	if (hk_insn_is_b(insn)) {
		off = hk_insn_decode_imm26(insn);
		if (off > 0) {
			return (unsigned long)((s64)pc + off);
		}
	}
	return 0;
}

static inline bool hk_is_func_prologue(u32 insn)
{
	if (hk_insn_is_pad(insn)) {
		return true;
	}
	if (hk_insn_is_stp_fp_lr(insn)) {
		return true;
	}
	return false;
}

unsigned long hk_unwrap_trampoline_depth(unsigned long addr, unsigned int max_hops)
{
	unsigned long visited[HK_MAX_BRANCH_HOPS];
	unsigned long lit_addr;
	unsigned long lit_val;
	unsigned long next;
	unsigned long pc;
	s64 off;
	u32 insn0;
	u32 insn1;
	int hops;
	int i;

	if (!max_hops) {
		max_hops = HK_DEFAULT_BRANCH_HOPS;
	}
	if (max_hops > HK_MAX_BRANCH_HOPS) {
		max_hops = HK_MAX_BRANCH_HOPS;
	}

	for (hops = 0; hops < max_hops; hops++) {
		if (!addr || !hk_ker_addr_ok(addr) || (addr & 3)) {
			return addr;
		}

		visited[hops] = addr;

		insn0 = 0;
		if (copy_from_kernel_nofault(&insn0, (const void *)addr, sizeof(insn0))) {
			break;
		}

		pc = addr;
		if (hk_insn_is_pad(insn0)) {
			pc += 4;
			insn0 = 0;
			if (copy_from_kernel_nofault(&insn0, (const void *)pc, sizeof(insn0))) {
				break;
			}
		}

		if (hk_insn_is_b(insn0)) {
			off = hk_insn_decode_imm26(insn0);
			next = (unsigned long)((s64)pc + off);
			if (next == addr || !hk_ker_addr_ok(next) || (next & 3)) {
				break;
			}
			for (i = 0; i <= hops; i++) {
				if (visited[i] == next) {
					return next;
				}
			}
			addr = next;
			continue;
		}

		if ((insn0 & HK_INSN_LDR_LIT_X16_MASK) == HK_INSN_LDR_LIT_X16_VAL) {
			insn1 = 0;
			if (copy_from_kernel_nofault(&insn1, (const void *)(pc + 4), sizeof(insn1)) == 0) {
				if (insn1 == HK_INSN_BR_X16) {
					lit_addr = (unsigned long)((s64)pc + hk_insn_decode_imm19(insn0));
					if ((lit_addr & 7) == 0 && hk_ker_addr_ok(lit_addr)) {
						lit_val = 0;
						if (copy_from_kernel_nofault(&lit_val, (const void *)lit_addr, sizeof(lit_val)) == 0) {
							if (lit_val && lit_val != addr &&
							    hk_ker_addr_ok(lit_val) && (lit_val & 3) == 0) {
								for (i = 0; i <= hops; i++) {
									if (visited[i] == lit_val) {
										return lit_val;
									}
								}
								addr = lit_val;
								continue;
							}
						}
					}
				}
			}
		}

		break;
	}

	return addr;
}

unsigned long hk_unwrap_trampoline(unsigned long addr)
{
	return hk_unwrap_trampoline_depth(addr, HK_DEFAULT_BRANCH_HOPS);
}

static bool hk_match_target(unsigned long target, unsigned long callee_addr,
			    unsigned long unwrapped_callee, unsigned int max_hops)
{
	unsigned long real_target;

	if (target == callee_addr || target == unwrapped_callee) {
		return true;
	}

	real_target = hk_unwrap_trampoline_depth(target, max_hops);
	if (real_target == callee_addr || real_target == unwrapped_callee) {
		return true;
	}

	return false;
}

int hk_probe_call_site(struct hk_call_site *site)
{
	unsigned long cur_addr;
	unsigned long target;
	unsigned long max_forward_pc;
	unsigned long fwd;
	unsigned long next;
	unsigned long unwrapped_callee;
	unsigned long unwrapped_caller;
	size_t limit;
	size_t next_words;
	size_t end_words;
	size_t size_words;
	size_t i;
	unsigned int effective_hops;
	u32 first_insn;
	u32 insn;
	bool ret_seen;
	bool has_explicit_bound;

	if (!site) {
		return -EINVAL;
	}

	site->bl_count = 0;
	site->b_count = 0;
	site->scanned_insns = 0;
	site->offset_count = 0;
	site->flags = 0;
	site->state = HK_CALL_STATE_UNKNOWN;

	if (!site->caller_addr && site->caller_name) {
		site->caller_addr = hk_resolve(site->caller_name);
	}
	if (!site->callee_addr && site->callee_name) {
		site->callee_addr = hk_resolve(site->callee_name);
	}

	if (!site->caller_addr || !site->callee_addr) {
		site->state = HK_CALL_STATE_NOT_FOUND;
		return -ENOENT;
	}

	if ((site->caller_addr & 3) || (site->callee_addr & 3)) {
		site->state = HK_CALL_STATE_ERROR;
		return -EINVAL;
	}

	if (!hk_ker_addr_ok(site->caller_addr) || !hk_ker_addr_ok(site->callee_addr)) {
		site->state = HK_CALL_STATE_ERROR;
		return -EINVAL;
	}

	if ((site->caller_size & 3) || (site->caller_end & 3)) {
		site->state = HK_CALL_STATE_ERROR;
		return -EINVAL;
	}

	if (site->caller_size > 0 && site->caller_size < 4) {
		site->state = HK_CALL_STATE_ERROR;
		return -EINVAL;
	}

	if (site->caller_end > 0 && site->caller_end <= site->caller_addr) {
		site->state = HK_CALL_STATE_ERROR;
		return -EINVAL;
	}

	if (site->caller_end > site->caller_addr && (site->caller_end - site->caller_addr) < 4) {
		site->state = HK_CALL_STATE_ERROR;
		return -EINVAL;
	}

	effective_hops = site->max_hops ? site->max_hops : HK_DEFAULT_BRANCH_HOPS;
	if (effective_hops > HK_MAX_BRANCH_HOPS) {
		effective_hops = HK_MAX_BRANCH_HOPS;
	}

	unwrapped_callee = hk_unwrap_trampoline_depth(site->callee_addr, effective_hops);

	if (!site->caller_size && !site->caller_end) {
		unwrapped_caller = hk_unwrap_trampoline_depth(site->caller_addr, effective_hops);
		if (hk_match_target(unwrapped_caller, site->callee_addr, unwrapped_callee, effective_hops)) {
			first_insn = 0;
			site->b_count = 1;
			site->offsets[0] = 0;
			site->offset_count = 1;
			site->scanned_insns = 1;
			if (copy_from_kernel_nofault(&first_insn,
			    (const void *)site->caller_addr, sizeof(first_insn)) == 0) {
				if (hk_insn_is_pad(first_insn)) {
					site->offsets[0] = 4;
					site->scanned_insns = 2;
				}
			}
			site->state = HK_CALL_STATE_TAIL;
			return 0;
		}
		if (!hk_ker_addr_ok(unwrapped_caller) || (unwrapped_caller & 3)) {
			site->state = HK_CALL_STATE_ERROR;
			return -EINVAL;
		}
		site->caller_addr = unwrapped_caller;
	}

	limit = site->max_insns ? site->max_insns : HK_DEFAULT_MAX_INSNS;
	if (limit > HK_HARD_MAX_INSNS) {
		limit = HK_HARD_MAX_INSNS;
	}
	has_explicit_bound = false;

	if (site->caller_size > 0) {
		size_words = site->caller_size / 4;
		if (size_words < limit) {
			limit = size_words;
		}
		has_explicit_bound = true;
	}

	if (site->caller_end > site->caller_addr) {
		end_words = (site->caller_end - site->caller_addr) / 4;
		if (end_words < limit) {
			limit = end_words;
		}
		has_explicit_bound = true;
	}

	if (!has_explicit_bound) {
		next = hk_resolve_next(site->caller_addr);
		if (next && next > site->caller_addr &&
		    (next & 3) == 0 && hk_ker_addr_ok(next)) {
			next_words = (next - site->caller_addr) / 4;
			if (next_words < limit) {
				limit = next_words;
			}
			site->caller_end = next;
			has_explicit_bound = true;
		}
	}

	ret_seen = false;
	max_forward_pc = site->caller_addr;

	for (i = 0; i < limit; i++) {
		cur_addr = site->caller_addr + (i * 4);
		insn = 0;

		if (copy_from_kernel_nofault(&insn, (const void *)cur_addr, sizeof(insn))) {
			site->scanned_insns = i;
			site->flags |= HK_SITE_F_FAULT;
			site->state = HK_CALL_STATE_ERROR;
			site->bl_count = 0;
			site->b_count = 0;
			site->offset_count = 0;
			return -EFAULT;
		}

		if (!has_explicit_bound) {
			if (cur_addr <= max_forward_pc) {
				ret_seen = false;
			} else if (ret_seen) {
				if (hk_insn_is_nop(insn)) {
					continue;
				}
				if (hk_is_func_prologue(insn)) {
					break;
				}
			}
		}

		fwd = decode_forward_branch(insn, cur_addr);
		if (fwd > max_forward_pc && hk_ker_addr_ok(fwd)) {
			max_forward_pc = fwd;
		}

		if (hk_insn_is_bl(insn)) {
			target = (unsigned long)((s64)cur_addr + hk_insn_decode_imm26(insn));
			if (hk_match_target(target, site->callee_addr, unwrapped_callee, effective_hops)) {
				if (site->offset_count < HK_SITE_MAX_OFFSETS) {
					site->offsets[site->offset_count++] = (u32)(i * 4);
				} else {
					site->flags |= HK_SITE_F_TRUNCATED;
				}
				site->bl_count++;
			}
		} else if (hk_insn_is_b(insn)) {
			target = (unsigned long)((s64)cur_addr + hk_insn_decode_imm26(insn));
			if (hk_match_target(target, site->callee_addr, unwrapped_callee, effective_hops)) {
				if (site->offset_count < HK_SITE_MAX_OFFSETS) {
					site->offsets[site->offset_count++] = (u32)(i * 4);
				} else {
					site->flags |= HK_SITE_F_TRUNCATED;
				}
				site->b_count++;
			}
		} else if (hk_insn_is_ret(insn)) {
			ret_seen = true;
		}
	}

	site->scanned_insns = i;

	if (site->bl_count > 0) {
		site->state = HK_CALL_STATE_LIVE;
	} else if (site->b_count > 0) {
		site->state = HK_CALL_STATE_TAIL;
	} else {
		site->state = HK_CALL_STATE_NO_DIRECT_CALL;
	}

	return 0;
}

int hk_probe_call_sites(struct hk_call_site *sites, size_t count)
{
	size_t i;
	int ret;
	int err;

	if (!sites) {
		return -EINVAL;
	}

	ret = 0;

	for (i = 0; i < count; i++) {
		err = hk_probe_call_site(&sites[i]);
		if (err && !ret) {
			ret = err;
		}
	}

	return ret;
}
