// runqlat.bpf.c
#include "../vmlinux.h"
#include "runqlat.h"
#include "utils.hpp"
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// 唤醒时间戳，key: tid -> value: ts_ns
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 131072);
} wake_ts SEC(".maps");

// 直方图（per-CPU，降低冲突），key 固定 0
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct hist);
} hists SEC(".maps");

// 运行时配置（rodata）
const volatile struct cfg conf = {
    .target_tgid = 0,
    .target_tid = 0,
    .threshold_ns = 0,
    .unit = UNIT_US,
};

static __always_inline bool pass_filter(struct task_struct *p) {
  __u32 pid = BPF_CORE_READ(p, pid);
  __u32 tgid = BPF_CORE_READ(p, tgid);
  if (conf.target_tgid && tgid != conf.target_tgid)
    return false;
  if (conf.target_tid && pid != conf.target_tid)
    return false;
  return pid != 0;
}

static __always_inline __u64 to_unit(__u64 delta_ns) {
  if (conf.unit == UNIT_NS)
    return delta_ns ? delta_ns : 1;
  if (conf.unit == UNIT_MS)
    return delta_ns / 1000000ULL ? delta_ns / 1000000ULL : 1;
  /* default UNIT_US */
  return delta_ns / 1000ULL ? delta_ns / 1000ULL : 1;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(on_wakeup, struct task_struct *p) {
  if (!pass_filter(p))
    return 0;
  __u32 pid = BPF_CORE_READ(p, pid);
  __u64 now = bpf_ktime_get_ns();
  bpf_map_update_elem(&wake_ts, &pid, &now, BPF_ANY);
  return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(on_wakeup_new, struct task_struct *p) { return on_wakeup(p); }

SEC("tp_btf/sched_switch")
int BPF_PROG(on_sched_switch, struct task_struct *prev,
             struct task_struct *next) {
  if (!pass_filter(next))
    return 0;

  __u32 next_pid = BPF_CORE_READ(next, pid);
  __u64 *ts = bpf_map_lookup_elem(&wake_ts, &next_pid);
  if (!ts)
    return 0; // 没有唤醒记录（例如被抢占后再次运行），不计 runqlat

  __u64 now = bpf_ktime_get_ns();
  __u64 delta = now - *ts;
  bpf_map_delete_elem(&wake_ts, &next_pid);

  if (conf.threshold_ns && delta < conf.threshold_ns)
    return 0;

  // 单位换算 + log2 分桶
  __u64 v = to_unit(delta);
  int slot = log2l_u64(v);
  if (slot < 0)
    slot = 0;
  if (slot >= MAX_SLOTS)
    slot = MAX_SLOTS - 1;

  __u32 key = 0;
  struct hist *h = bpf_map_lookup_elem(&hists, &key);
  if (!h)
    return 0;
  __sync_fetch_and_add(&h->slots[slot], 1);
  return 0;
}
