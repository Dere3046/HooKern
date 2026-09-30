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

query through the injected resolver. 0 when unset or unresolved. when
the injected resolver has nothing, or the library is between `hk_exit`
and the next `hk_init`, the kernel symbol table is walked once for a
`name$type` entry, which is what a clang CFI build calls the body of a
function whose address was taken, and that body is returned.

**void hk_exit_block(void)**

the end of a module's exit path, for a module whose kernel text still
branches into a hook. it never returns while a hook is live: it retries
`hk_inline_exit` and `hk_ptr_exit` every 60 seconds and only returns
once every count is zero. rmmod unmaps module text and data as soon as
the exit path returns, so a live detour without this points into freed
memory.

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

writes to read-only kernel memory through a fixmap slot. the target
virtual address is translated without any self-written page table
walk: kernel image addresses (inside `_text`/`_end`, resolved lazily)
use `kimage_voffset` (VA_BITS independent), a linear mapping uses
`__pa`, and the vmalloc window goes through the kernel's exported
`vmalloc_to_pfn` (module vmalloc memory) after `find_vm_area` says the
address is a registered area, where that symbol exists. an address
that matches no path is refused with a code instead of being handed to
a walk that would read a block mapping as a page table.

the slot named by a call is an index into the early ioremap window:
slot 0 is `FIX_BTMAP_END`, which is `__end_of_permanent_fixed_addresses`
in every build of this series, so the numbering starts above the
permanent part and can never reach `FIX_TEXT_POKE0`, the kernel's own
patch slot, or `FIX_ENTRY_TRAMP_TEXT1` to `TEXT4`, where the KPTI entry
trampoline is mapped. slots 0 to `HK_PATCH_SLOT_LIMIT - 1` (8) are
accepted, anything else is -EINVAL before `__set_fixmap` runs, whose
own guard is a `BUG_ON`. a write opens one slot, stores and unmaps it
again, and the unmapping is on the only path that mapped it.

the flags word carries the slot in bits 16 to 23 and the write mode in
bits 8 to 15, both 0 by default. modes are `HK_PATCH_MODE_SLOT` (0,
the library slot, one instruction directly and several from a
stop_machine callback), `HK_PATCH_MODE_INSN_PATCH` (1, the kernel's
`aarch64_insn_patch_text` under `cpus_read_lock`, which is a
`stop_machine_cpuslocked` wrapper and asserts the lock is held, up to
`HK_PATCH_INSNS_MAX` instructions) and `HK_PATCH_MODE_INSN_WRITE` (2,
the kernel's `aarch64_insn_write`, one word at a time, caller flushes).
every mode is process context, the calls sleep.

**int hk_patch_write(void *dst, unsigned long val)**

write a single word. the fast path for pointer replacement. -EINVAL on
a bad argument, -ENOENT when a symbol the path needs is absent, -EIO
when the address matches no translation path, -EFAULT when the page
cannot be reached.

**int hk_patch_text(void *dst, const void *src, size_t len, int flags)**

write any length, per page fixmap mapping, one instruction directly and
any longer run from a stop_machine callback. flags are
`HK_PATCH_FLUSH_ICACHE`, `HK_PATCH_FLUSH_DCACHE`, a mode and a slot.
`len` must be a multiple of four. failures are returned, never
swallowed: -EINVAL, -ENOENT, -EIO, -EFAULT and -E2BIG for a kernel mode
run over `HK_PATCH_INSNS_MAX` words.

**int hk_patch_text_at(void *dst, const void *src, size_t len, int flags,
unsigned int slot)** and **int hk_patch_write_at(void *dst, unsigned long
val, int flags)** are the explicit forms; the plain calls above are the
same with the slot from the flags word or 0.

**int hk_patch_prepare(struct hk_patch_set *set, struct hk_patch_hook *hook)**

the precheck of a transaction. nothing is written: the destination is
translated, the current bytes are read through the nofault helper into
`hook->orig` and checksummed into `hook->checksum`, and the hook joins
the set. -EALREADY on a hook prepared twice, -EINVAL on a bad argument
or a length over `HK_PATCH_INSNS_MAX` words, and the translation codes
above. both structs are caller owned.

**int hk_patch_commit(struct hk_patch_set *set)**

every site is compared against the bytes the prepare saw before the
first write, so a site another writer took is -EAGAIN with nothing
changed. a write that fails after that point puts the sites already
written back, so a set is all in or all out, and the failing code is
returned.

**int hk_patch_rollback(struct hk_patch_set *set)**

restore the sites the set has active. the first failure is returned, a
hook that could not be restored stays active for a later call.
**void hk_patch_set_init(struct hk_patch_set *set)** and **void
hk_patch_set_release(struct hk_patch_set *set)** start and empty a set,
release does not write, and **unsigned int hk_patch_set_count(const
struct hk_patch_set *set)** counts the hooks in it.

the hook set is what a hot replacement is built on: prepare every new
hook, commit the set, then unhook the old ones.

## Inline hook

**int hk_inline_hook(struct hk_inline *h, const char *sym, const char
*wrapper_sym)**

replace the entry of sym with a 20 byte detour and build an internal
exec trampoline. the wrapper is resolved from wrapper_sym and invoked
through an absolute LDR X17 + RET X17 jump, so there is no plus or minus 128 MB
range limit. h->orig points to the trampoline entry, call it from the
wrapper to run the original function.

the library records the window of every live hook. an install whose
window overlaps one is refused with -EBUSY, the log line names both
symbols, nothing is written. hk_inline_probe answers the same condition
before an install is attempted.

installs are serialized by a mutex held across trampoline allocation,
relocation and the text writes, so two hooks cannot interleave and a
restore cannot run inside an install. the write itself is still not
atomic with respect to a core executing the target, the lock removes
the second writer only, so a hot path other cores run during
installation still belongs to the kprobe entries. stop_machine is not
used: this path allocates and resolves symbols and a stop_machine
callback must do neither, so a prepare and commit split has to come
before the callback can carry the last write.

the detour covers HK_INLINE_PATCH_LEN bytes from the entry, so the
entry needs that much room of its own. a shorter symbol shares its
window with the next function, hk_inline_probe reports the length.

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
	bool pending;
	bool use_br_x17;
	struct hk_inline_guard guard[HK_INLINE_GUARD_MAX];
	u32 guard_count;
	u8 saved[HK_INLINE_ENTRY_MAX * 4];
};
```

the continuation after the patched window is reached with an indirect
branch, so the pages that hold one and carry the guarded attribute have
it cleared for the install and put back when the trampoline is freed,
recorded in `guard` and counted by `guard_count`. when the attribute
cannot be cleared the continuation uses `RET X17` instead of `BR X17`,
which is a return and needs no landing pad, and `use_br_x17` reports
which of the two is in the trampoline.

**int hk_inline_disable(struct hk_inline *h)**

restore the original entry but keep the trampoline alive. use before
waiting for in-flight calls. runs under the same install lock. the
window is released with the restore, a later install can take it. -EIO
when the write fails, the hook stays live, the window stays held and
the trampoline stays allocated, call it again.

**void hk_inline_free(struct hk_inline *h)**

free the trampoline after disable and release the window. safe to call
on a zeroed hook.

**void hk_inline_unhook(struct hk_inline *h)**

the three stage unload: disable the entry, wait one `synchronize_rcu_tasks`
grace period so a core that already fetched the detour is out of the
trampoline, then free it. a hook whose entry could not be restored is
parked, the trampoline is kept and `hk_inline_pending` counts it, and
`hk_inline_exit` retries every parked hook. that count is what
`hk_exit_block` gates the module exit on.

**int hk_inline_probe(const char *sym, struct hk_inline_probe *out)**

read only half of hk_inline_hook, for a caller that wants to judge a
live hot path before it is patched. it resolves sym, follows the same
branch chain, reads the entry window through the nofault helper and
runs the relocator over a copy of it. it writes nothing, allocates
nothing, does not sleep and never allocates exec memory. 0 when the
report was filled, -EINVAL on a NULL argument.

```c
struct hk_inline_probe {
	unsigned long addr;	/* resolver result, 0 when unresolved */
	unsigned long target;	/* entry a hook would patch, chain followed */
	u32 patch_len;		/* bytes the detour overwrites there */
	enum hk_inline_state state;
	const char *reason;	/* static string, the caller never owns it */
	unsigned long collide_addr;	/* start of the window in the way */
};
```

```
HK_INLINE_UNRESOLVED   sym did not resolve, addr is 0
HK_INLINE_UNREADABLE   the entry window could not be read
HK_INLINE_UNSUPPORTED  the relocator refuses the window, an operand in it
                       points back into the window, or addr is not a
                       kernel address
HK_INLINE_HOOKED       a jump stub sits in the window: br, brk, ldr plus br,
                       or a movz movk chain ending in br
HK_INLINE_PATCHSITE    an ftrace patch site: mov x9, x30 at the entry, with
                       nop or bl behind it
HK_INLINE_BRANCHED     a direct b in the entry, target is where a hook would
                       write, the end of the chain when the walk follows it
                       and the entry itself when it does not
HK_INLINE_PLAIN        no known stub, the relocator accepts the window
HK_INLINE_COLLISION    a live hook owns part of the window, an install
                       would return -EBUSY, collide_addr is its start
```

the collision answer comes from the window table the installs keep, so it
holds for the hooks already live when the probe runs.

every state except plain means the entry should not be patched as it
stands. plain is signature based: an adrp add br stub, a patch that
keeps the first instructions, and an ftrace site on a kernel whose
ftrace patches a bare nop are not recognised, so plain means no known
stub was found, it is not proof of an untouched prologue.

## Pointer replacement

**int hk_ptr_hook(void **slot, void *replacement, void **orig_out)**

read the pointer at slot, replace it, record the original in the
tracking list. one lock is held across the duplicate check, the read,
the swap and the record, so two hooks cannot interleave and lose an
original; the swap itself is a single aligned word store, a core that
reads the slot sees the old pointer or the new one. the list has no
fixed capacity, the walk over the live hooks costs what the old 16 slot
table scan did. the tracking entry is allocated, so this runs in
process context. -EEXIST when the slot is already hooked. -EFAULT when
the slot cannot be read. -EIO when the write fails. -ENOMEM when the
tracking entry cannot be allocated, there is no full table any more.
the original is written to orig_out on success.

**void hk_ptr_unhook(void **slot)**

restore the recorded original. silent when the slot is not hooked.

**void hk_ptr_exit(void)**

restore every tracked slot. called by hk_exit.

## Kprobe

kprobe is the entry for a target other cores can execute during
installation. register_kprobe arms its breakpoint under text_mutex and
cpus_read_lock, so a hot path like device_add can be probed while the
inline primitive must not patch it. the price is the handler contract:
a probe observes a call, it does not replace the function, and calling
the target from a handler re-enters the same probe. use kprobe for a
hot target, for an entry window hk_inline_probe reports as
HK_INLINE_PATCHSITE, an ftrace patch site the relocator would lose, and
for a window it reports as HK_INLINE_UNSUPPORTED.

**int hk_kprobe_install(struct hk_kprobe *h, const char *sym, kprobe_pre_handler_t pre)**

register a kprobe on sym with the given pre handler. the resolved
address lands in h->orig. register_kprobe and unregister_kprobe are
resolved at runtime through `__nocfi` wrappers, some GKI builds trim
the exports, a missing symbol fails with -ENODATA. a refused install
logs the symbol, the kernel code and the gate that fired, and returns
the kernel code: -EINVAL for every address gate, -ENOENT for a symbol
that does not resolve. -ENOMEM when the tracking node cannot be
allocated, nothing is registered then, there is no ceiling on the
number of live probes. hk_kprobe_remove logs when the probe cannot be
unregistered again, a probe left armed on module text is a use after
free, and a second remove of the same hook is a no op.

```c
struct hk_kprobe {
	struct kprobe kp;
	unsigned long orig;
};
```

**int hk_kprobe_check(const char *sym, struct hk_kprobe_report *out)**

ask the address gates of register_kprobe before an install and name the
one that would refuse the symbol, the way hk_inline_probe judges an
inline target. nothing is written, nothing is allocated and it does not
sleep. 0 when the report was filled, -EINVAL on a NULL argument.

```c
struct hk_kprobe_report {
	unsigned long addr;	/* resolver result, 0 when unresolved */
	enum hk_kprobe_state state;
	const char *reason;	/* static string, the caller never owns it */
};

HK_KPROBE_UNRESOLVED   the resolver did not find the symbol, addr is 0
HK_KPROBE_UNSUPPORTED  not text, or a cfi preamble symbol
HK_KPROBE_BLACKLISTED  kprobe_blacklist, __kprobes or noinstr text, the
                       reason names hk_kprobe_clear_blacklist
HK_KPROBE_PATCHSITE    a recorded ftrace call site, refused on a kernel
                       without kprobes on ftrace, arm64 has none
HK_KPROBE_OK           no address gate matched
```

the gates are the kprobe ones for a kretprobe too, register_kretprobe
registers a kprobe. HK_KPROBE_OK is not a promise, an install can still
fail on a kernel symbol the resolver cannot reach or on a tracking node
that cannot be allocated.

**handler helpers**

arm64 carries the first eight arguments of a call in x0 to x7 and the
return value in x0. hk_regs_arg and hk_regs_set_arg read and write an
argument at an entry, hk_regs_ret and hk_regs_set_ret read and write
the return value where a kretprobe handler runs, hk_regs_ip returns the
pc, hk_regs_lr returns the link register, and hk_regs_skip steps the pc
over the probed instruction for a pre handler that returns 1.

the replacement idiom for a hot target is hk_regs_return, it parks the
pc on the link register so the target returns at once with x0 as the
result and its prologue never runs, which is as close to a wrapper as a
probe gets:

```c
static int pre(struct kprobe *p, struct pt_regs *regs)
{
	hk_regs_set_ret(regs, my_device_add(hk_regs_arg(regs, 0)));
	hk_regs_return(regs);
	return 1;
}
```

**void hk_kprobe_remove(struct hk_kprobe *h)** unregisters and untracks.
**void hk_kprobe_exit(void)** removes every tracked probe, called by
hk_exit.

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
(struct kretprobe_instance, struct pt_regs), it runs after the target
returned and the return value is in x0, so hk_regs_set_ret rewrites it,
which a kprobe cannot do. the kernel writes the registers back after
the handler. register_kretprobe and unregister_kretprobe are runtime
resolved like the kprobe ones. the address gates are the kprobe ones,
so hk_kprobe_check answers for a kretprobe target, and a refused
install logs the symbol, the kernel code and the gate. installs are
tracked in a list like the kprobe ones, no ceiling and no -ENOSPC,
-ENOMEM when the tracking node cannot be allocated. the target has to
return, a function that never returns leaks instances until maxactive
runs out and the probe then misses returns instead of failing the
install.

**int hk_kretprobe_install_ex(struct hk_kretprobe *h, const char *sym, kretprobe_handler_t entry, kretprobe_handler_t handler, size_t data_size)**

the entry and return pair. the entry handler runs at the call, returns
1 to accept the instance and can fill ri->data with data_size bytes,
which the return handler reads back from the same instance.

```c
struct hk_kretprobe {
	struct kretprobe rp;
};
```

**void hk_kretprobe_remove(struct hk_kretprobe *h)** and **void
hk_kretprobe_exit(void)** mirror the kprobe ones, including the log line
when the probe cannot be unregistered again.

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
