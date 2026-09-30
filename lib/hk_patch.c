// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 dere3046
 */

#include <linux/crc32.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <asm/fixmap.h>
#include <asm/memory.h>
#include <asm/pgtable.h>

#include "hk.h"
#include "hk_patch.h"

/*
 * the base is the first slot of the early ioremap window and not FIX_TEXT_POKE0.
 * the enum between the two is not spare: a kernel with UNMAP_KERNEL_AT_EL0 adds
 * FIX_ENTRY_TRAMP_TEXT1 to TEXT4 above FIX_TEXT_POKE0, the KPTI entry
 * trampoline is mapped there by map_entry_trampoline, and a patch that opened
 * one of those slots and unmapped it again would clear a live trampoline page
 * table entry. FIX_BTMAP_END is __end_of_permanent_fixed_addresses in every
 * build of this series, so it sits above the whole permanent window including
 * the trampoline slots, and the window it starts is the boot only early ioremap
 * one, which nothing holds after early_ioremap_reset
 */
#define HK_FIXMAP_SLOT_BASE FIX_BTMAP_END
#define HK_FIXMAP_SLOT_MAX HK_PATCH_SLOT_LIMIT

typedef void (*clean_inval_fn)(unsigned long start, unsigned long end);
typedef void (*fixmap_fn)(unsigned long idx, phys_addr_t phys, pgprot_t prot);
typedef int (*insn_write_fn)(void *addr, u32 insn);
typedef int (*insn_patch_fn)(void *addr[], u32 insn[], int count);
typedef struct vm_struct *(*find_vm_area_fn)(const void *addr);

/*
 * one mutex covers the whole path because the paths sleep: __set_fixmap flushes
 * a TLB, stop_machine parks the other cores and aarch64_insn_patch_text takes
 * cpus_read_lock. a spinlock cannot be held over any of them, so it is not held
 * at all and every caller is documented as process context
 */
static DEFINE_MUTEX(g_patch_lock);

static clean_inval_fn g_clean_inval;
static fixmap_fn g_set_fixmap;
static insn_write_fn g_insn_write;
static insn_patch_fn g_insn_patch;
static find_vm_area_fn g_find_vm_area;
static unsigned long (*g_vmalloc_to_pfn_fn)(const void *addr);
static unsigned long g_kimage_voffset;
static bool g_kimage_voffset_read;
static unsigned long g_image_start;
static unsigned long g_image_end;
static bool g_image_read;
static bool g_slot_broken;

/*
 * the index is an enum constant plus 0 to 7, so it folds at compile time and the
 * bound is checked then too: an index over FIX_BTMAP_BEGIN belongs to the page
 * table fixmaps at the end of the enum, which are live, and the check refuses it
 * before __set_fixmap, whose own guard is a BUG_ON. the dst warning in the write
 * path is the runtime half of the same answer, it probes the address the slot
 * actually resolved to
 */
static int hk_patch_slot_index(unsigned int slot, int *out)
{
	unsigned long idx;

	if (slot > HK_PATCH_SLOT_MASK || slot >= HK_FIXMAP_SLOT_MAX) {
		pr_warn("[lkmhook] fixmap slot %u is over the library range\n",
			slot);
		return -EINVAL;
	}
	idx = HK_FIXMAP_SLOT_BASE + slot;
	if (idx > FIX_BTMAP_BEGIN) {
		pr_warn("[lkmhook] fixmap slot %u lands outside the early ioremap window\n",
			slot);
		return -EINVAL;
	}
	*out = (int)idx;
	return 0;
}

static __nocfi noinline int call_clean_inval(unsigned long start,
					     unsigned long end)
{
	unsigned long fn;

	if (!g_clean_inval) {
		fn = hk_resolve("caches_clean_inval_pou");
		if (!fn)
			fn = hk_resolve("dcache_clean_inval_poc");
		if (!fn)
			fn = hk_resolve("__flush_icache_range");
		if (!fn) {
			pr_warn("[lkmhook] no cache clean fn, the write is refused\n");
			return -ENOENT;
		}
		g_clean_inval = (clean_inval_fn)fn;
	}
	g_clean_inval(start, end);
	return 0;
}

static __nocfi noinline int call_set_fixmap(unsigned long idx,
					    phys_addr_t phys, pgprot_t prot)
{
	if (!g_set_fixmap) {
		unsigned long fn = hk_resolve("__set_fixmap");

		if (!fn) {
			pr_warn("[lkmhook] __set_fixmap not found, the write is refused\n");
			return -ENOENT;
		}
		g_set_fixmap = (fixmap_fn)fn;
	}
	g_set_fixmap(idx, phys, prot);
	return 0;
}

/*
 * the copy goes through the alias __set_fixmap just opened, the only way into
 * read only text, and it is a plain memcpy that faults with no way back. the gate
 * therefore runs before every store and a destination that is not mapped is
 * refused with -ENXIO instead of being written. it is a page table walk and not
 * a probe: a probe reports the same thing but only after the walk has already
 * answered, and a walk cannot be fooled by a slot that maps a page of zeros
 *
 * the walk is the one the kernel itself uses on init_mm, so it stays correct for
 * whatever paging levels the running kernel was built with. a block mapping at
 * any level means there is no pte to read and the gate refuses
 */
static unsigned long *hk_dst_pte(unsigned long addr)
{
	struct mm_struct *mm;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	mm = (struct mm_struct *)hk_resolve("init_mm");
	if (!mm || !hk_ker_addr_ok((unsigned long)mm))
		return NULL;
	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return NULL;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return NULL;
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		return NULL;
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return NULL;
	return (unsigned long *)pte_offset_kernel(pmd, addr);
}

/*
 * -ENXIO when the alias the slot resolved to is not mapped, 0 when it is. the
 * address a slot computes is a compile time frame offset from FIXADDR_TOP, and
 * FIXADDR_TOP is a constant of the build this module was compiled against while
 * the window that exists is a constant of the running kernel. the two differ
 * whenever the kernel's VA_BITS or VMEMMAP_SHIFT is not the one in the headers
 * the module was built with, and then the alias sits outside the window and the
 * store faults instead of failing. this is the gate that turns that into an
 * error the caller can act on
 */
static int hk_patch_dst_check(unsigned long va, int idx, unsigned long caller)
{
	unsigned long *ptep = hk_dst_pte(va);

	if (ptep && pte_present(__pte(READ_ONCE(*ptep))))
		return 0;
#if HK_PATCH_DST_CHECK
	pr_warn("[lkmhook] fixmap %d dest 0x%lx is not a mapped page, caller 0x%lx, refused\n",
		idx, va, caller);
#endif
	return -ENXIO;
}

/*
 * a refused alias is a property of the build pair and not of one address, so the
 * first refusal takes the slot path out for good. every later write goes straight
 * to the kernel's own primitive, whose frame is the kernel's
 */
static void hk_slot_disable(const char *why)
{
	if (g_slot_broken)
		return;
	g_slot_broken = true;
	pr_warn("[lkmhook] slot path disabled for this module: %s, every later write uses the kernel patch primitive\n",
		why);
}

/*
 * image addresses are the one range virt_addr_valid cannot answer for: the image
 * sits in the vmalloc window, so the linear mapping test fails on it while __pa
 * would subtract the wrong offset. _text and _end are the bounds and both are
 * read once. the answer is a plain range test, a bare virtual address inside the
 * image is never handed to vmalloc_to_pfn, whose pmd walk reads a block mapping
 * as if it were a pte table and returns a physical address from unrelated page
 * contents. a kernel without the two symbols answers false and the vmalloc
 * branch is gated by find_vm_area instead
 */
static bool hk_kernel_image_addr(unsigned long addr)
{
	unsigned long start;
	unsigned long end;

	if (!g_image_read) {
		start = hk_resolve("_text");
		if (!start)
			start = hk_resolve("_stext");
		end = hk_resolve("_end");
		if (!end)
			end = hk_resolve("__bss_stop");
		g_image_read = true;
		if (!start || !end || end <= start ||
		    !hk_ker_addr_ok(start) || !hk_ker_addr_ok(end)) {
			pr_warn_once("[lkmhook] _text/_end unavailable, image addresses fall to the vmalloc branch\n");
			return false;
		}
		g_image_start = start;
		g_image_end = end;
	}
	return g_image_start && addr >= g_image_start && addr < g_image_end;
}

/*
 * every translation path a patch can take ends here. the caller decides what to
 * write, this decides whether the address is a kernel text or data address and
 * refuses the rest with a code. the result is a physical address of the page the
 * fixmap alias is opened on
 */
static __nocfi noinline int hk_translate(unsigned long addr, unsigned long *out)
{
	unsigned long fn;
	unsigned long phys;
	unsigned long pfn;
	unsigned long voff;
	bool image;

	/*
	 * the order matters. the image range is asked first because it is the one
	 * test that needs a symbol, and a caller that names an address no path can
	 * reach gets -EIO with no walk attempted, so a runaway value cannot reach
	 * vmalloc_to_pfn and come back with a physical address built from whatever
	 * the pmd entry it read happened to hold
	 */
	image = hk_kernel_image_addr(addr);
	if (!image && !__is_lm_address(addr) && !is_vmalloc_addr((void *)addr)) {
		pr_warn("[lkmhook] 0x%lx is not a kernel address this build can reach\n",
			addr);
		return -EIO;
	}

	if (image) {
		if (!g_kimage_voffset_read) {
			fn = hk_resolve("kimage_voffset");
			if (!fn || !hk_ker_addr_ok(fn)) {
				pr_warn("[lkmhook] kimage_voffset not found, image addresses cannot be translated\n");
				return -ENOENT;
			}
			if (copy_from_kernel_nofault(&voff, (void *)fn,
						     sizeof(voff))) {
				pr_warn("[lkmhook] kimage_voffset unreadable\n");
				return -EFAULT;
			}
			g_kimage_voffset = voff;
			g_kimage_voffset_read = true;
		}
		if (!g_kimage_voffset) {
			pr_warn("[lkmhook] kimage_voffset is zero\n");
			return -EINVAL;
		}
		*out = addr - g_kimage_voffset;
		return 0;
	}

	if (__is_lm_address(addr)) {
		*out = __pa(addr);
		return 0;
	}

	if (!g_find_vm_area) {
		fn = hk_resolve("find_vm_area");
		if (fn && hk_ker_addr_ok(fn))
			g_find_vm_area = (find_vm_area_fn)fn;
	}
	if (g_find_vm_area && !g_find_vm_area((const void *)addr)) {
		pr_warn("[lkmhook] 0x%lx is not a registered vmalloc area\n",
			addr);
		return -EIO;
	}
	if (!g_vmalloc_to_pfn_fn) {
		fn = hk_resolve("vmalloc_to_pfn");
		if (!fn || !hk_ker_addr_ok(fn)) {
			pr_warn("[lkmhook] vmalloc_to_pfn not found, the write is refused\n");
			return -ENOENT;
		}
		g_vmalloc_to_pfn_fn = (unsigned long (*)(const void *))fn;
	}
	pfn = g_vmalloc_to_pfn_fn((const void *)addr);
	if (!pfn) {
		pr_warn("[lkmhook] 0x%lx has no page\n", addr);
		return -EFAULT;
	}
	phys = (pfn << PAGE_SHIFT) + (addr & ~PAGE_MASK);
	*out = phys;
	return 0;
}

struct hk_patch_job {
	unsigned long addr;
	const void *src;
	size_t len;
	int flags;
	int idx;
	unsigned long caller;
	atomic_t arrived;
	int ret;
	/*
	 * released by the master once the slot is closed and the writes are done,
	 * the other cpus spin on it before they return from the callback
	 */
	int done;
};

/*
 * the write through the alias. one slot serves any length, the alias is opened
 * per physical page and dropped again. the caller holds g_patch_lock, so the
 * slot is not shared and neither is the kernel patch slot
 */
static int hk_patch_slot_run(unsigned long addr, const void *src, size_t len,
			     int flags, int idx, unsigned long caller)
{
	size_t left = len;
	int ret = 0;

	while (left) {
		unsigned long phys;
		unsigned long fixmap_va;
		size_t chunk;

		ret = hk_translate(addr, &phys);
		if (ret)
			break;
		chunk = min(left, PAGE_SIZE - (phys & ~PAGE_MASK));

		ret = call_set_fixmap(idx, phys & PAGE_MASK, PAGE_KERNEL);
		if (ret)
			break;
		fixmap_va = __fix_to_virt(idx) + (phys & ~PAGE_MASK);
		ret = hk_patch_dst_check(fixmap_va, idx, caller);
		if (ret) {
			call_set_fixmap(idx, 0, __pgprot(0));
			break;
		}
		memcpy((void *)fixmap_va, src, chunk);
		dsb(ish);
		call_set_fixmap(idx, 0, __pgprot(0));

		if (flags & HK_PATCH_FLUSH_DCACHE) {
			ret = call_clean_inval(addr, addr + chunk);
			if (ret)
				break;
		}
		if (flags & HK_PATCH_FLUSH_ICACHE)
			hk_flush_icache(addr);

		src += chunk;
		addr += chunk;
		left -= chunk;
	}
	return ret;
}

/*
 * one fixmap slot and one page table entry are shared by the whole machine, so
 * only one of the stopped cpus may open it. the last one to arrive is the master,
 * the others spin until it is done, which is what the kernel's own patcher does
 * for the same reason. without this every stopped cpu opens and closes the slot
 * under the others and a cpu that passed the destination gate can lose the entry
 * before its store lands
 */
static int hk_patch_slot_cb(void *data)
{
	struct hk_patch_job *job = data;

	if (atomic_inc_return(&job->arrived) != num_online_cpus()) {
		while (!smp_load_acquire(&job->done))
			cpu_relax();
		return 0;
	}
	job->ret = hk_patch_slot_run(job->addr, job->src, job->len, job->flags,
				     job->idx, job->caller);
	smp_store_release(&job->done, 1);
	return job->ret;
}

typedef struct module *(*hk_module_address_fn)(unsigned long addr);

/*
 * the module a text or data address belongs to, NULL for anything else. the
 * symbol is resolved at runtime. it is asked before the slot path is entered
 * because a module address has a page table the kernel's own patch primitive
 * already knows how to reach, while the frame the slot path computes is a build
 * constant of this module and does not have to be the one the running kernel
 * mapped its fixmap window with
 */
static bool hk_is_module_addr(unsigned long addr)
{
	static hk_module_address_fn fn;
	static bool tried;

	if (!tried) {
		unsigned long sym = hk_resolve("__module_address");

		tried = true;
		if (sym && hk_ker_addr_ok(sym))
			fn = (hk_module_address_fn)sym;
	}
	return fn && fn(addr) != NULL;
}

/*
 * the kernel's own patch primitive, stop_machine inside. stop_machine_cpuslocked
 * asserts that cpus_read_lock is held, kprobe and ftrace call it from under
 * theirs, so it is taken here. the symbol is resolved at runtime because it is
 * not exported
 */
static __nocfi int hk_insn_patch_once(unsigned long addr, const void *src,
				     size_t len)
{
	void *addrs[HK_PATCH_INSNS_MAX];
	u32 insns[HK_PATCH_INSNS_MAX];
	const u32 *in = src;
	int count = (int)(len / 4);
	int ret;
	int i;

	if ((len & 3) || (addr & 3)) {
		pr_warn("[lkmhook] insn patch wants a word aligned range\n");
		return -EINVAL;
	}
	if (count < 1 || count > HK_PATCH_INSNS_MAX) {
		pr_warn("[lkmhook] insn patch takes 1 to %d instructions\n",
			HK_PATCH_INSNS_MAX);
		return -E2BIG;
	}


	for (i = 0; i < count; i++) {
		addrs[i] = (void *)(addr + i * 4);
		insns[i] = in[i];
	}
	if (!g_insn_patch) {
		unsigned long fn = hk_resolve("aarch64_insn_patch_text");

		if (!fn) {
			pr_warn("[lkmhook] aarch64_insn_patch_text not found\n");
			return -ENOENT;
		}
		g_insn_patch = (insn_patch_fn)fn;
	}

	cpus_read_lock();
	ret = g_insn_patch(addrs, insns, count);
	cpus_read_unlock();
	if (ret)
		return ret;
	return call_clean_inval(addr, addr + len);
}

/*
 * the primitive takes a table of addresses and is bounded by HK_PATCH_INSNS_MAX,
 * which is what its own callers use, so a longer run is split into calls of that
 * size. the whole run is still covered by cpus_read_lock around each call and by
 * the caller's g_patch_lock across all of them
 */
static int hk_insn_patch_run(unsigned long addr, const void *src, size_t len)
{
	size_t chunk;
	int ret;

	while (len) {
		chunk = min_t(size_t, len, HK_PATCH_INSNS_MAX * 4);
		ret = hk_insn_patch_once(addr, src, chunk);
		if (ret)
			return ret;
		addr += chunk;
		src += chunk;
		len -= chunk;
	}
	return 0;
}

/*
 * the kernel's own slot, one instruction at a time, caller flushes. the address
 * has to be readable as a vmalloc or image address for the kernel's own
 * translation, so it is checked here before the call
 */
static __nocfi int hk_insn_write_run(unsigned long addr, const void *src,
				     size_t len)
{
	const u32 *in = src;
	unsigned long start = addr;
	unsigned long left = len;
	unsigned long phys;
	int ret;

	if ((len & 3) || (addr & 3) || ((addr & ~PAGE_MASK) + len) > PAGE_SIZE) {
		pr_warn("[lkmhook] insn write wants one aligned page of words\n");
		return -EINVAL;
	}
	ret = hk_translate(addr, &phys);
	if (ret)
		return ret;
	if (!g_insn_write) {
		unsigned long fn = hk_resolve("aarch64_insn_write");

		if (!fn) {
			pr_warn("[lkmhook] aarch64_insn_write not found\n");
			return -ENOENT;
		}
		g_insn_write = (insn_write_fn)fn;
	}
	cpus_read_lock();
	while (left) {
		ret = g_insn_write((void *)addr, *in);
		if (ret)
			break;
		addr += 4;
		in++;
		left -= 4;
	}
	cpus_read_unlock();
	if (ret)
		return ret;
	ret = call_clean_inval(start, start + len);
	if (ret)
		return ret;
	hk_flush_icache(start);
	return 0;
}

int hk_patch_text_at(void *dst, const void *src, size_t len, int flags,
		     unsigned int slot)
{
	struct hk_patch_job job;
	unsigned long addr = (unsigned long)dst;
	unsigned long caller = (unsigned long)__builtin_return_address(0);
	unsigned int mode = (flags >> HK_PATCH_MODE_SHIFT) & HK_PATCH_MODE_MASK;
	int ret;

	if (!dst || !src || !len || (len & 3))
		return -EINVAL;
	if (slot > HK_PATCH_SLOT_MASK)
		return -EINVAL;
	if (mode > HK_PATCH_MODE_INSN_WRITE)
		return -EINVAL;

	mutex_lock(&g_patch_lock);
	ret = hk_patch_slot_index(slot, &job.idx);
	if (ret) {
		pr_warn("[lkmhook] fixmap slot %u is not usable, %d\n", slot,
			ret);
		goto out;
	}
	job.addr = addr;
	job.src = src;
	job.len = len;
	job.flags = flags;
	job.caller = caller;
	atomic_set(&job.arrived, 0);
	job.done = 0;
	job.ret = 0;

	if (g_slot_broken && mode != HK_PATCH_MODE_INSN_PATCH)
		mode = HK_PATCH_MODE_INSN_PATCH;

	/*
	 * a module address is written by the kernel's own primitive whichever
	 * mode was asked for. its patch_map reaches the page through the module
	 * page table and through the kernel's own fixmap frame, so it is correct
	 * on a kernel whose VA_BITS is not the one this module was built with,
	 * which is exactly the case the slot path cannot survive
	 */
	if (mode == HK_PATCH_MODE_SLOT && hk_is_module_addr(addr))
		mode = HK_PATCH_MODE_INSN_PATCH;

	if (mode == HK_PATCH_MODE_INSN_PATCH) {
		ret = hk_insn_patch_run(addr, src, len);
	} else if (mode == HK_PATCH_MODE_INSN_WRITE) {
		ret = hk_insn_write_run(addr, src, len);
	} else if (len <= 4) {
		ret = hk_patch_slot_run(addr, src, len, flags, job.idx,
					caller);
		if (ret == -ENXIO) {
			hk_slot_disable("the alias is outside the running kernel fixmap window");
			ret = hk_insn_patch_run(addr, src, len);
		}
	} else {
		struct hk_patch_job saved = job;

		ret = stop_machine(hk_patch_slot_cb, &job, cpu_online_mask);
		/*
		 * the slot frame is a constant of this build and the frame of the
		 * running kernel is not, so the alias can land outside the kernel's
		 * fixmap window. the destination gate answers that with -ENXIO
		 * before the store, and the kernel's own primitive is then the only
		 * write path left that still has the right frame
		 */
		if (ret == -ENXIO) {
			hk_slot_disable("the alias is outside the running kernel fixmap window");
			ret = hk_insn_patch_run(saved.addr, saved.src,
						saved.len);
		}
	}
	if (ret)
		pr_warn("[lkmhook] patch 0x%lx+%zu mode %u failed %d\n",
			addr, len, mode, ret);
out:
	mutex_unlock(&g_patch_lock);
	return ret;
}

int hk_patch_text(void *dst, const void *src, size_t len, int flags)
{
	return hk_patch_text_at(dst, src, len, flags, HK_PATCH_SLOT_DEFAULT);
}

int hk_patch_write_at(void *dst, unsigned long val, int flags)
{
	unsigned int slot = (flags >> HK_PATCH_SLOT_SHIFT) & HK_PATCH_SLOT_MASK;

	return hk_patch_text_at(dst, &val, sizeof(val), flags, slot);
}

int hk_patch_write(void *dst, unsigned long val)
{
	return hk_patch_text_at(dst, &val, sizeof(val),
				HK_PATCH_FLUSH_DCACHE | HK_PATCH_FLUSH_ICACHE,
				HK_PATCH_SLOT_DEFAULT);
}

void hk_patch_set_init(struct hk_patch_set *set)
{
	if (!set)
		return;
	INIT_LIST_HEAD(&set->hooks);
	INIT_LIST_HEAD(&set->list);
	set->count = 0;
}

unsigned int hk_patch_set_count(const struct hk_patch_set *set)
{
	return set ? set->count : 0;
}

/*
 * the precheck. nothing is written, the current bytes are read through the
 * nofault helper and kept with their checksum, and every reason an install could
 * fail is answered here so the commit that follows has none left
 */
int hk_patch_prepare(struct hk_patch_set *set, struct hk_patch_hook *hook)
{
	unsigned long phys;
	int ret;

	if (!set || !hook || !hook->dst || !hook->src || !hook->len)
		return -EINVAL;
	if (hook->prepared || hook->active)
		return -EALREADY;
	if (hook->len > sizeof(hook->orig) || (hook->len & 3))
		return -EINVAL;

	ret = hk_translate((unsigned long)hook->dst, &phys);
	if (ret) {
		pr_warn("[lkmhook] prepare %s: 0x%lx does not translate, %d\n",
			hook->name ? hook->name : "?",
			(unsigned long)hook->dst, ret);
		return ret;
	}
	if (copy_from_kernel_nofault(hook->orig, hook->dst, hook->len)) {
		pr_warn("[lkmhook] prepare %s: site is not readable\n",
			hook->name ? hook->name : "?");
		return -EFAULT;
	}
	hook->checksum = crc32_le(~0U, hook->orig, hook->len);
	hook->prepared = true;
	hook->active = false;
	if (!hook->list.next) {
		list_add_tail(&hook->list, &set->hooks);
		set->count++;
	}
	return 0;
}

/*
 * the commit. every site is compared against the bytes the prepare saw before
 * the first write, so a site another writer took is reported while nothing has
 * changed. a write that fails after that point puts the sites already written
 * back and reports the failure, so a set is either all in or all out
 */
int hk_patch_commit(struct hk_patch_set *set)
{
	struct hk_patch_hook *hook;
	struct hk_patch_hook *failed = NULL;
	u8 seen[HK_PATCH_INSNS_MAX * 4];
	int ret = 0;

	if (!set)
		return -EINVAL;

	list_for_each_entry(hook, &set->hooks, list) {
		if (!hook->prepared) {
			pr_warn("[lkmhook] commit %s: not prepared\n",
				hook->name ? hook->name : "?");
			return -EINVAL;
		}
		if (copy_from_kernel_nofault(seen, hook->dst, hook->len)) {
			pr_warn("[lkmhook] commit %s: site is not readable\n",
				hook->name ? hook->name : "?");
			return -EFAULT;
		}
		if (crc32_le(~0U, seen, hook->len) != hook->checksum) {
			pr_warn("[lkmhook] commit %s: site changed since prepare\n",
				hook->name ? hook->name : "?");
			return -EAGAIN;
		}
	}

	list_for_each_entry(hook, &set->hooks, list) {
		ret = hk_patch_text_at(hook->dst, hook->src, hook->len,
				       hook->flags,
				       (hook->flags >> HK_PATCH_SLOT_SHIFT) &
					       HK_PATCH_SLOT_MASK);
		if (ret) {
			failed = hook;
			break;
		}
		hook->active = true;
	}
	if (!ret)
		return 0;

	list_for_each_entry(hook, &set->hooks, list) {
		if (hook == failed)
			break;
		hk_patch_text_at(hook->dst, hook->orig, hook->len,
				 hook->flags | HK_PATCH_FLUSH_ICACHE |
					 HK_PATCH_FLUSH_DCACHE,
				 (hook->flags >> HK_PATCH_SLOT_SHIFT) &
					 HK_PATCH_SLOT_MASK);
		hook->active = false;
	}
	pr_warn("[lkmhook] commit rolled back at %s, %d\n",
		failed && failed->name ? failed->name : "?", ret);
	return ret;
}

int hk_patch_rollback(struct hk_patch_set *set)
{
	struct hk_patch_hook *hook;
	int first = 0;

	if (!set)
		return -EINVAL;

	list_for_each_entry(hook, &set->hooks, list) {
		int ret;

		if (!hook->active)
			continue;
		ret = hk_patch_text_at(hook->dst, hook->orig, hook->len,
				       hook->flags | HK_PATCH_FLUSH_ICACHE |
					       HK_PATCH_FLUSH_DCACHE,
				       (hook->flags >>
					HK_PATCH_SLOT_SHIFT) &
					       HK_PATCH_SLOT_MASK);
		if (ret) {
			pr_warn("[lkmhook] rollback %s failed %d\n",
				hook->name ? hook->name : "?", ret);
			if (!first)
				first = ret;
			continue;
		}
		hook->active = false;
	}
	return first;
}

void hk_patch_set_release(struct hk_patch_set *set)
{
	struct hk_patch_hook *hook;
	struct hk_patch_hook *tmp;

	if (!set)
		return;
	list_for_each_entry_safe(hook, tmp, &set->hooks, list) {
		list_del(&hook->list);
		hook->prepared = false;
		set->count--;
	}
	INIT_LIST_HEAD(&set->hooks);
	set->count = 0;
}
