# Makefile
BPF_CLANG ?= clang
LLVM_STRIP ?= llvm-strip
CFLAGS ?= -O2 -g
LDFLAGS ?=

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LDLIBS := $(shell pkg-config --libs libbpf 2>/dev/null)
ifeq ($(LIBBPF_CFLAGS),)
LIBBPF_LDLIBS := -lbpf -lelf -lz
endif

all: offcpu.bpf.o offcpu.skel.h offcpu

offcpu.bpf.o: offcpu.bpf.c offcpu.h
	$(BPF_CLANG) -target bpf -D__TARGET_ARCH_x86 -O2 -g -c $< -o $@
	$(LLVM_STRIP) -g $@

offcpu.skel.h: offcpu.bpf.o
	bpftool gen skeleton $< > $@

offcpu: offcpu_user.c offcpu.h offcpu.skel.h
	$(CC) $(CFLAGS) -Wall -Wextra -o $@ offcpu_user.c $(LIBBPF_CFLAGS) $(LIBBPF_LDLIBS) $(LDFLAGS)

clean:
	rm -f offcpu.bpf.o offcpu.skel.h offcpu
