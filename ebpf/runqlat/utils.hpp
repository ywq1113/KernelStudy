
#pragma once
#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static __always_inline int log2l_u64(__u64 v) {
  // bpf helper bpf_get_prandom_u32 不可用；自己算 log2。v=0 归到 0 槽。
  int r = 0;
  if (v >> 32) {
    v >>= 32;
    r += 32;
  }
  if (v >> 16) {
    v >>= 16;
    r += 16;
  }
  if (v >> 8) {
    v >>= 8;
    r += 8;
  }
  if (v >> 4) {
    v >>= 4;
    r += 4;
  }
  if (v >> 2) {
    v >>= 2;
    r += 2;
  }
  if (v >> 1) {
    r += 1;
  }
  return r;
}