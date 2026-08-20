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

writes to read-only kernel memory through the fixmap slot. the target
virtual address is translated without any self-written page table
walk: kernel image addresses (inside `_text`/`_end`, resolved lazily)
use `kimage_voffset` (VA_BITS independent), everything else goes
through the kernel's exported `vmalloc_to_pfn` (module vmalloc
memory). FIX_TEXT_POKE0 is mapped to the page with PAGE_KERNEL and
the bytes are written through the fixmap alias.

**int hk_patch_write(void *dst, unsigned long val)**

write a single word under a spinlock. the fast path for pointer
replacement. -EIO when the address cannot be translated.

**int hk_patch_text(void *dst, const void *src, size_t len, int flags)**

write any length under a spinlock with per-page fixmap mapping. flags
are HK_PATCH_FLUSH_ICACHE and HK_PATCH_FLUSH_DCACHE. no
stop_machine: on 5.10 old CFI its indirect call BR's into the module
cfi_jt stub (bti c entry) which trips BTI on guarded module pages.

## Inline hook

**int hk_inline_hook(struct hk_inline *h, const char *sym, const char
*wrapper_sym)**

replace the entry of sym with a 20 byte detour and build an internal
exec trampoline. the wrapper is resolved from wrapper_sym and invoked
through an absolute LDR X17 + RET X17 jump, so there is no ±128 MB
range limit. h->orig points to the trampoline entry, call it from the
wrapper to run the original function.

wrapper_sym must be a global symbol (LTO localizes static ones and
drops the names from kallsyms). addresses come from the resolver, not
from &func.

trampoline layout:

```
+0x00  bti jc
+0x04  ldr x17, #8
+0x08  ret x17
+0x0c  wrapper low
+0x10  wrapper high
+0x14  bti jc          trampoline entry, h->orig
+0x18  saved window    relocated original instructions
+...   ldr x17 + ret   jump back to func+window
```

```c
struct hk_inline {
	const char *name;
	unsigned long addr;
	unsigned long orig;
	void *mem;
	size_t mem_size;
	u32 window;
	bool disabled;
	u8 saved[HK_INLINE_ENTRY_MAX * 4];
};
```

**int hk_inline_disable(struct hk_inline *h)**

restore the original entry but keep the trampoline alive. use before
waiting for in-flight calls.

**void hk_inline_free(struct hk_inline *h)**

free the trampoline after disable. safe to call on a zeroed hook.

**void hk_inline_unhook(struct hk_inline *h)**

disable then free.

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

**int hk_kprobe_clear_blacklist(void)**

resolve the global `kprobe_blacklist`, save every active entry and
zero its start/end so protected functions can be probed. returns 0 on
success, -ENOENT when the list symbol is missing, -ENOMEM when the
save array cannot be allocated. call this explicitly before installing
probes on blacklisted symbols, it is not called by hk_kprobe_install.

**void hk_kprobe_restore_blacklist(void)**

restore the saved start/end addresses and free the save array. called
automatically by hk_kprobe_exit, safe to call manually before exit.

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

## Binder trace

**int hk_binder_init(const struct hk_binder_callbacks *cb)**

install inline hooks on binder_ioctl,
binder_alloc_copy_user_to_buffer and binder_transaction (optional).
symbols are resolved with a CFI `$` suffix fallback. the callbacks are
invoked before the original function. init also calls hk_cfi_bypass()
so old-CFI indirect calls through file_operations do not panic.
returns 0 on success, -EINVAL on NULL callbacks, -ENOENT when the
required binder symbols are missing.

**void hk_binder_exit(void)**

set draining, disable all hooks, synchronize_rcu_tasks (resolved at
runtime, missing symbol is a no-op), wait for in-flight wrappers and
free the trampolines.

```c
struct hk_binder_callbacks {
	void (*ioctl)(void *priv, void *filp, unsigned int cmd,
		      unsigned long arg);
	void (*copy_from_user)(void *priv, void *alloc, void *buffer,
			       unsigned long buffer_offset,
			       const void __user *from, size_t bytes);
	void (*transaction)(void *priv,
			    const struct hk_binder_transaction_event *ev);
	void *priv;
};
```

## LSM hook

LSM hook is an optional component compiled with `HK_LSM=1`. it
replaces existing LSM hook slots at runtime. Type_info is vendored
under deps/Type_info and injected through a pointer layout, so the
library does not link Type_info directly.

```c
struct hk_lsm_layout {
	unsigned long (*resolve)(const char *name);
	int (*type_by_name)(const char *name, u32 *id);
	int (*member_off)(u32 id, const char *member, u32 *bit_off,
			  u32 *bit_sz);
	u32 (*type_size)(u32 id);
};
```

**int hk_lsm_init(const struct hk_lsm_layout *layout)**

store the injected Type_info layout. must be called before any
hk_lsm_hook.

**int hk_lsm_hook(struct hk_lsm_hook *hook)**

find the LSM slot whose current handler matches target_name and
replace it with replacement. supports legacy security_hook_heads
(< 6.12) and static_calls_table (>= 6.12).

**void hk_lsm_unhook(struct hk_lsm_hook *hook)**

restore the original handler and untrack the hook.

**int hk_lsm_register(struct hk_lsm_hook *hook)** and **void
hk_lsm_unregister(struct hk_lsm_hook *hook)** are aliases of
hk_lsm_hook / hk_lsm_unhook.

**void hk_lsm_exit(void)**

restore all tracked hooks and clear the injected layout.

```c
#define HK_LSM_HOOK_INIT(member, target_symbol, replacement_fn, off) \
	{                                                              \
		.head_name = #member,                                  \
		.target_name = target_symbol,                          \
		.head_offset = offsetof(HK_LSM_HEADS_TYPE, member),    \
		.hook_offset = offsetof(struct security_hook_list, hook.member),\
		.replacement = (void *)(replacement_fn),               \
		.offset = off,                                         \
	}
```

when a Type_info layout is injected, hk_lsm uses layout->member_off
to resolve security_hook_list and lsm_static_call offsets at runtime,
so compile-time offsetof values are only a fallback.
