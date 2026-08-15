// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <linux/stop_machine.h>
#include <asm/cacheflush.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>

#include "hk.h"
#include "hk_patch.h"

typedef void (*clean_inval_fn)(unsigned long start, unsigned long end);
typedef void (*fixmap_fn)(unsigned long idx, phys_addr_t phys,
			  pgprot_t prot);

static DEFINE_SPINLOCK(patch_lock);

static struct mm_struct *g_init_mm;
static clean_inval_fn g_clean_inval;
static fixmap_fn g_set_fixmap;

static bool ker_addr_ok(unsigned long v)
{
	return v >= 0xffff000000000000UL;
}

static unsigned long virt_to_phys_walk(unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (!ker_addr_ok(addr))
		return 0;
	if (!g_init_mm) {
		g_init_mm = (struct mm_struct *)hk_resolve("init_mm");
		if (!g_init_mm) {
			pr_warn("[lkmhook] init_mm not found\n");
			return 0;
		}
	}

	pgd = pgd_offset(g_init_mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return 0;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return 0;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return 0;
#if defined(pud_leaf)
	if (pud_leaf(*pud))
		return __pud_to_phys(*pud) + (addr & ~PUD_MASK);
#endif
	if (pud_bad(*pud))
		return 0;

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return 0;
#if defined(pmd_leaf)
	if (pmd_leaf(*pmd))
		return __pmd_to_phys(*pmd) + (addr & ~PMD_MASK);
#endif
	if (pmd_bad(*pmd))
		return 0;

	pte = pte_offset_kernel(pmd, addr);
	if (!pte || !pte_present(*pte))
		return 0;

	return __pte_to_phys(*pte) + (addr & ~PAGE_MASK);
}

static __nocfi void call_clean_inval(unsigned long start, unsigned long end)
{
	if (!g_clean_inval) {
		g_clean_inval = (clean_inval_fn)hk_resolve(
			"caches_clean_inval_pou");
		if (!g_clean_inval)
			g_clean_inval = (clean_inval_fn)hk_resolve(
				"dcache_clean_inval_poc");
		if (!g_clean_inval)
			g_clean_inval = (clean_inval_fn)hk_resolve(
				"flush_dcache_range");
		if (!g_clean_inval) {
			pr_warn("[lkmhook] no cache clean fn\n");
			return;
		}
	}
	g_clean_inval(start, end);
}

static __nocfi void call_set_fixmap(unsigned long idx, phys_addr_t phys,
				    pgprot_t prot)
{
	if (!g_set_fixmap) {
		g_set_fixmap = (fixmap_fn)hk_resolve("__set_fixmap");
		if (!g_set_fixmap) {
			pr_warn("[lkmhook] __set_fixmap not found\n");
			return;
		}
	}
	g_set_fixmap(idx, phys, prot);
}

int hk_patch_write(void *dst, unsigned long val)
{
	unsigned long phys;
	unsigned long fixmap_va;
	unsigned long flags;
	unsigned long addr = (unsigned long)dst;

	spin_lock_irqsave(&patch_lock, flags);
	phys = virt_to_phys_walk(addr);
	if (!phys) {
		spin_unlock_irqrestore(&patch_lock, flags);
		return -EIO;
	}
	call_set_fixmap(FIX_TEXT_POKE0, phys & PAGE_MASK, PAGE_KERNEL);
	fixmap_va = fix_to_virt(FIX_TEXT_POKE0) + (phys & ~PAGE_MASK);
	*(unsigned long *)fixmap_va = val;
	dsb(ish);
	call_set_fixmap(FIX_TEXT_POKE0, 0, __pgprot(0));
	spin_unlock_irqrestore(&patch_lock, flags);

	call_clean_inval(addr, addr + sizeof(val));
	return 0;
}

struct patch_info {
	void *dst;
	const void *src;
	size_t len;
	int flags;
	atomic_t cpu_count;
};

bool hk_patch_guarded(void *addr)
{
	unsigned long v = (unsigned long)addr;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (!ker_addr_ok(v))
		return false;
	if (!g_init_mm) {
		g_init_mm = (struct mm_struct *)hk_resolve("init_mm");
		if (!g_init_mm)
			return false;
	}

	pgd = pgd_offset(g_init_mm, v);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return false;

	p4d = p4d_offset(pgd, v);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return false;

	pud = pud_offset(p4d, v);
	if (pud_none(*pud))
		return false;
#if defined(pud_leaf)
	if (pud_leaf(*pud))
		return !!(pud_val(*pud) & PTE_GP);
#endif
	if (pud_bad(*pud))
		return false;

	pmd = pmd_offset(pud, v);
	if (pmd_none(*pmd))
		return false;
#if defined(pmd_leaf)
	if (pmd_leaf(*pmd))
		return !!(pmd_val(*pmd) & PTE_GP);
#endif
	if (pmd_bad(*pmd))
		return false;

	pte = pte_offset_kernel(pmd, v);
	if (!pte || !pte_present(*pte))
		return false;
	return !!(pte_val(*pte) & PTE_GP);
}

static int __nocfi patch_text_cb(void *arg)
{
	struct patch_info *p = arg;
	unsigned long addr = (unsigned long)p->dst;
	size_t left = p->len;
	int ret = 0;

	if (atomic_inc_return(&p->cpu_count) != num_online_cpus()) {
		while (atomic_read(&p->cpu_count) <= num_online_cpus())
			cpu_relax();
		isb();
		return 0;
	}

	while (left) {
		unsigned long phys;
		unsigned long fixmap_va;
		size_t chunk;

		phys = virt_to_phys_walk(addr);
		if (!phys) {
			ret = -ENOENT;
			break;
		}
		chunk = min(left, PAGE_SIZE - (phys & ~PAGE_MASK));

		call_set_fixmap(FIX_TEXT_POKE0, phys & PAGE_MASK,
				PAGE_KERNEL);
		fixmap_va = fix_to_virt(FIX_TEXT_POKE0) +
			    (phys & ~PAGE_MASK);
		memcpy((void *)fixmap_va, p->src, chunk);
		call_set_fixmap(FIX_TEXT_POKE0, 0, __pgprot(0));

		if (p->flags & HK_PATCH_FLUSH_DCACHE)
			call_clean_inval(addr, addr + chunk);
		if (p->flags & HK_PATCH_FLUSH_ICACHE) {
			asm volatile("ic ivau, %0" :: "r"(addr));
			asm volatile("dsb ish");
			asm volatile("isb");
		}

		p->src += chunk;
		addr += chunk;
		left -= chunk;
	}

	atomic_inc(&p->cpu_count);
	return ret;
}

int hk_patch_text(void *dst, const void *src, size_t len, int flags)
{
	struct patch_info info = {
		.dst = dst,
		.src = src,
		.len = len,
		.flags = flags,
		.cpu_count = ATOMIC_INIT(0),
	};

	if (!dst || !src || !len)
		return -EINVAL;

	return stop_machine(patch_text_cb, &info, cpu_online_mask);
}
