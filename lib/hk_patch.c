// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/spinlock.h>
#include <asm/cacheflush.h>
#include <asm/fixmap.h>
#include <asm/pgtable.h>

#include "hk.h"
#include "hk_patch.h"

typedef void (*clean_inval_fn)(unsigned long start, unsigned long end);
typedef void (*fixmap_fn)(unsigned long idx, phys_addr_t phys,
			  pgprot_t prot);

static DEFINE_SPINLOCK(patch_lock);

static clean_inval_fn g_clean_inval;
static fixmap_fn g_set_fixmap;
static unsigned long g_kimage_voffset;
static unsigned long g_text;
static unsigned long g_end;
static unsigned long (*g_vmalloc_to_pfn_fn)(const void *addr);

static bool ker_addr_ok(unsigned long v)
{
	return v >= 0xffff000000000000UL;
}

static bool kernel_image_addr(unsigned long addr)
{
	if (!g_text || !g_end) {
		g_text = hk_resolve("_text");
		g_end = hk_resolve("_end");
		if (!g_text || !g_end || !ker_addr_ok(g_text) ||
		    !ker_addr_ok(g_end)) {
			g_text = g_end = 0;
			return false;
		}
	}
	return addr >= g_text && addr < g_end;
}

static __nocfi noinline unsigned long find_kernel_phys(unsigned long addr)
{
	unsigned long fn;
	unsigned long voff;
	unsigned long pfn;

	if (kernel_image_addr(addr)) {
		if (!g_kimage_voffset) {
			fn = hk_resolve("kimage_voffset");
			if (!fn || !ker_addr_ok(fn)) {
				pr_warn("[lkmhook] kimage_voffset not found\n");
				return 0;
			}
			if (copy_from_kernel_nofault(&voff, (void *)fn,
						     sizeof(voff))) {
				pr_warn("[lkmhook] kimage_voffset unreadable\n");
				return 0;
			}
			g_kimage_voffset = voff;
		}
		return addr - g_kimage_voffset;
	}

	if (!is_vmalloc_addr((void *)addr))
		return 0;
	if (!g_vmalloc_to_pfn_fn) {
		fn = hk_resolve("vmalloc_to_pfn");
		if (!fn || !ker_addr_ok(fn)) {
			pr_warn("[lkmhook] vmalloc_to_pfn not found\n");
			return 0;
		}
		g_vmalloc_to_pfn_fn = (unsigned long (*)(const void *))fn;
	}
	pfn = g_vmalloc_to_pfn_fn((const void *)addr);
	if (!pfn)
		return 0;
	return (pfn << PAGE_SHIFT) + (addr & ~PAGE_MASK);
}

static __nocfi noinline void call_clean_inval(unsigned long start, unsigned long end)
{
	unsigned long fn;

	if (!g_clean_inval) {
		fn = hk_resolve("caches_clean_inval_pou");
		if (fn)
			g_clean_inval = (clean_inval_fn)fn;
		if (!g_clean_inval) {
			fn = hk_resolve("dcache_clean_inval_poc");
			if (fn)
				g_clean_inval = (clean_inval_fn)fn;
		}
		if (!g_clean_inval) {
			fn = hk_resolve("flush_dcache_range");
			if (fn)
				g_clean_inval = (clean_inval_fn)fn;
		}
		if (!g_clean_inval) {
			fn = hk_resolve("__flush_icache_range");
			if (fn)
				g_clean_inval = (clean_inval_fn)fn;
		}
		if (!g_clean_inval) {
			pr_warn("[lkmhook] no cache clean fn\n");
			return;
		}
	}
	g_clean_inval(start, end);
}

static __nocfi noinline void call_set_fixmap(unsigned long idx, phys_addr_t phys,
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
	phys = find_kernel_phys(addr);
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

static int __nocfi patch_text_locked(unsigned long addr, const void *src,
				     size_t len, int flags)
{
	size_t left = len;
	int ret = 0;

	while (left) {
		unsigned long phys;
		unsigned long fixmap_va;
		size_t chunk;

		phys = find_kernel_phys(addr);
		if (!phys) {
			ret = -ENOENT;
			break;
		}
		chunk = min(left, PAGE_SIZE - (phys & ~PAGE_MASK));

		call_set_fixmap(FIX_TEXT_POKE0, phys & PAGE_MASK,
				PAGE_KERNEL);
		fixmap_va = fix_to_virt(FIX_TEXT_POKE0) +
			    (phys & ~PAGE_MASK);
		memcpy((void *)fixmap_va, src, chunk);
		call_set_fixmap(FIX_TEXT_POKE0, 0, __pgprot(0));

		if (flags & HK_PATCH_FLUSH_DCACHE)
			call_clean_inval(addr, addr + chunk);
		if (flags & HK_PATCH_FLUSH_ICACHE)
			hk_flush_icache(addr);

		src += chunk;
		addr += chunk;
		left -= chunk;
	}
	return ret;
}

int hk_patch_text(void *dst, const void *src, size_t len, int flags)
{
	unsigned long lock_flags;
	int ret;

	if (!dst || !src || !len)
		return -EINVAL;

	spin_lock_irqsave(&patch_lock, lock_flags);
	ret = patch_text_locked((unsigned long)dst, src, len, flags);
	spin_unlock_irqrestore(&patch_lock, lock_flags);
	return ret;
}
