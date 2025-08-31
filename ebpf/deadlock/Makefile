BPF_CLANG ?= clang
BPF_LLVM_STRIP ?= llvm-strip
CFLAGS := -O2 -g
LDFLAGS :=

CXX=g++


# 如果系统没有 pkg-config 的 libbpf 配置，fallback 到通用链路
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LDLIBS := $(shell pkg-config --libs libbpf 2>/dev/null)
ifeq ($(LIBBPF_CFLAGS),)
LIBBPF_LDLIBS := -lbpf -lelf -lz
endif


all: deadlock.bpf.o deadlock.skel.h deadlock_user


# 1) 编译 eBPF 对象（CO-RE）
deadlock.bpf.o: deadlock.bpf.c
	$(BPF_CLANG) -target bpf -D__TARGET_ARCH_x86 -O2 -g \
		-c $< -o $@
	$(BPF_LLVM_STRIP) -g $@


# 2) 生成 skeleton（需要 bpftool）
deadlock.skel.h: deadlock.bpf.o
	bpftool gen skeleton $< > $@


# 3) 编译用户态
deadlock_user: deadlock_user.cpp deadlock.skel.h
	$(CXX) $(CFLAGS) deadlock_user.cpp -o $@ $(LIBBPF_CFLAGS) $(LIBBPF_LDLIBS)

clean:
	rm -f deadlock.bpf.o deadlock.skel.h deadlock_user