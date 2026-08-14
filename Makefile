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

ifeq ($(TEST),1)
lkmhook-y += test/self_test.o
ccflags-y += -DHK_SELF_TEST
endif

KALLRECON_REV := 8d647f07ac66d380cdaa1cff8c168a8ab24c1c3b
KALLRECON_URL := https://github.com/Dere3046/KallRecon.git

ifeq ($(KDIR),)
$(error KDIR must be set, e.g. "make KDIR=/path/to/kernel-source")
endif
PWD := $(shell pwd)

deps:
	@if [ ! -f deps/KallRecon/lib/core.c ]; then \
		git clone --no-checkout $(KALLRECON_URL) deps/KallRecon; \
		git -C deps/KallRecon checkout $(KALLRECON_REV); \
	fi

all: deps
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
