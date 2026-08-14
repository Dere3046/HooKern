# LKMhook API

kernel hook library. resolves symbols through a pointer-injected
resolver, writes read-only kernel memory through the fixmap slot,
replaces function pointers with tracking, and wraps kprobe and
kretprobe.

## Layout injection

the library never links a layout source. the only kernel layout
capability is the injected resolver in `struct hk_cfg`, typically a
KallRecon wrapper. on old-CFI kernels the wrapper must be a
`__nocfi` function around `kallrecon_klp`, passing the raw pointer
makes the module's indirect call check fail with a CFI panic.

```c
struct hk_cfg {
	unsigned long (*resolve)(const char *name);
};
```

## Lifecycle

**int hk_init(const struct hk_cfg *cfg)**

the one call that starts everything. the cfg is copied by value, the
caller does not need to keep it alive. 0 on success. -EINVAL when cfg
or the resolver is bad. -EALREADY when already initialized, call
hk_exit first.

**void hk_exit(void)**

restores every tracked pointer, removes every installed probe and
clears state. safe to call multiple times.

**unsigned long hk_resolve(const char *name)**

query through the injected resolver. 0 when unset or unresolved.

## Symbols

**int hk_ksym_register(const struct hk_sym *table)**

batch resolve a NULL terminated table, optional fallback name per
entry, values stored through `storage`. -ENOENT when any required
entry fails, the count of missing ones is logged.

```c
struct hk_sym {
	const char *name;
	const char *fallback;
	void **storage;
	bool required;
};
```

## Patch

writes to read-only kernel memory through the fixmap slot. the
target virtual address is translated with a page table walk over
init_mm (works for the kernel image and module vmalloc memory), then
FIX_TEXT_POKE0 is mapped to the page with PAGE_KERNEL and the bytes
are written through the fixmap alias.

**int hk_patch_write(void *dst, unsigned long val)**

write a single word under a spinlock. the fast path for pointer
replacement. -EIO when the address cannot be translated.

**int hk_patch_text(void *dst, const void *src, size_t len, int flags)**

write any length through stop_machine with per-page fixmap mapping.
flags are HK_PATCH_FLUSH_ICACHE and HK_PATCH_FLUSH_DCACHE. the
stop_machine callback is `__nocfi`.

## Pointer replacement

**int hk_ptr_hook(void **slot, void *replacement, void **orig_out)**

read the pointer at slot, replace it, record the original. -EEXIST
when the slot is already hooked. -EFAULT when the slot cannot be
read. -ENOSPC when the tracking table (16 slots) is full. the
original is written to orig_out on success.

**void hk_ptr_unhook(void **slot)**

restore the recorded original. silent when the slot is not hooked.

**void hk_ptr_exit(void)**

restore every tracked slot. called by hk_exit.

## Kprobe

**int hk_kprobe_install(struct hk_kprobe *h, const char *sym, kprobe_pre_handler_t pre)**

register a kprobe on sym with the given pre handler. the resolved
address lands in h->orig. register_kprobe and unregister_kprobe are
resolved at runtime through `__nocfi` wrappers, some GKI builds trim
the exports, a missing symbol fails with -ENODATA. -ENOSPC when the
tracking table (16 slots) is full, the probe is unregistered again.

```c
struct hk_kprobe {
	struct kprobe kp;
	unsigned long orig;
};
```

**void hk_kprobe_remove(struct hk_kprobe *h)**

unregister and untrack. **void hk_kprobe_exit(void)** removes every
tracked probe, called by hk_exit.

## Kretprobe

**int hk_kretprobe_install(struct hk_kretprobe *h, const char *sym, kretprobe_handler_t handler)**

register a kretprobe on sym. the handler signature is the kernel one
(struct kretprobe_instance, struct pt_regs). register_kretprobe and
unregister_kretprobe are runtime resolved like the kprobe ones. same
tracking limits as kprobe.

```c
struct hk_kretprobe {
	struct kretprobe rp;
};
```

**void hk_kretprobe_remove(struct hk_kretprobe *h)** and **void
hk_kretprobe_exit(void)** mirror the kprobe ones.

## Behavior

**KCFI**

every caller that invokes a kernel function through a runtime
resolved pointer carries `__nocfi` (the fixmap and cache clean
helpers). `__nocfi` is real on GKI: 5.10 defines it unconditionally
as `no_sanitize("cfi")`, KCFI kernels define it as
`no_sanitize("kcfi")` when the module compiles with the sanitizer.
