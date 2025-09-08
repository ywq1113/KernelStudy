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

all: runqlat.bpf.o runqlat.skel.h runqlat

runqlat.bpf.o: runqlat.bpf.c runqlat.h
	$(BPF_CLANG) -target bpf -D__TARGET_ARCH_x86 -O2 -g -c $< -o $@
	$(LLVM_STRIP) -g $@

runqlat.skel.h: runqlat.bpf.o
	bpftool gen skeleton $< > $@

runqlat: runqlat_user.c runqlat.h runqlat.skel.h
	$(CC) $(CFLAGS) -Wall -Wextra -o $@ runqlat_user.c $(LIBBPF_CFLAGS) $(LIBBPF_LDLIBS) $(LDFLAGS)

clean:
	rm -f runqlat.bpf.o runqlat.skel.h runqlat
