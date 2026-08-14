obj-m := lkmhook.o

lkmhook-y := src/main.o lib/hk.o lib/hk_ksym.o lib/hk_patch.o lib/hk_ptr.o \
	lib/hk_kprobe.o lib/hk_kretprobe.o \
	deps/KallRecon/lib/core.o deps/KallRecon/lib/slide.o deps/KallRecon/lib/anchor.o

ccflags-y += -std=gnu11
ccflags-y += -Wno-declaration-after-statement
ccflags-y += -Wno-unused-variable
ccflags-y += -Wno-unused-function
ccflags-y += -Wno-strict-prototypes
ccflags-y += -I$(src)/lib
ccflags-y += -I$(src)/deps/KallRecon/lib

KALLRECON_REV := 8d647f07ac66d380cdaa1cff8c168a8ab24c1c3b
KALLRECON_URL := https://github.com/Dere3046/KallRecon.git

KDIR := $(KDIR)
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ODIR := $(MDIR)/out/$(VER)

$(info -- KDIR: $(KDIR))
$(info -- MDIR: $(MDIR))
$(info -- ODIR: $(ODIR))

all: deps
	make -C $(KDIR) M=$(ODIR) src=$(MDIR) modules

deps:
	@if [ ! -f deps/KallRecon/lib/core.c ]; then \
		git clone --no-checkout $(KALLRECON_URL) deps/KallRecon; \
		git -C deps/KallRecon checkout $(KALLRECON_REV); \
	fi

clean:
	make -C $(KDIR) M=$(ODIR) src=$(MDIR) clean

$(obj)/%.o: $(src)/%.c $(recordmcount_source) FORCE
	$(call if_changed_rule,cc_o_c)
	$(call cmd,force_checksrc)

$(obj)/%.o: $(src)/%.S FORCE
	$(call if_changed_rule,as_o_S)
