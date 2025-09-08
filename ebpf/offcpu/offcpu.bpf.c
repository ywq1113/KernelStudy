// offcpu.bpf.c
// CO-RE offcpu: 在 sched_switch 采样上一个被切出的任务的 off-CPU 段
#include "offcpu.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32); // pid (tid)
  __type(value, struct start_info);
  __uint(max_entries, 65536);
} starts SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_STACK_TRACE);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
  __uint(max_entries, 16384);
} stacks SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24); // 16MB
} rb SEC(".maps");

// 运行时配置（由 user 空间写入 .rodata）
struct {
  __u64 threshold_ns;
  __u32 target_tgid;   // 0: 不过滤
  __u8 sleep_only;     // 1: 仅统计 sleep (prev->state != 0) 的 offcpu
  __u8 capture_kernel; // 1: 采集内核栈
  __u8 capture_user;   // 1: 采集用户栈
} conf SEC(".rodata");

static __always_inline int get_kstack_id(void *ctx) {
  if (!conf.capture_kernel)
    return -1;
  // FAST_STACK_CMP 有利于去重
  return bpf_get_stackid(ctx, &stacks, BPF_F_FAST_STACK_CMP);
}

static __always_inline int get_ustack_id(void *ctx) {
  if (!conf.capture_user)
    return -1;
  // 采集用户态栈；需要内核开启 perf 相关能力
  return bpf_get_stackid(ctx, &stacks, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);
}

static __always_inline bool is_sleeping(long state) {
  // Runnning == 0；非 0 基本可视为 I/IO/UNINTERRUPTIBLE 等睡眠
  return state != 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(on_sched_switch, struct task_struct *prev,
             struct task_struct *next) {
  __u64 now = bpf_ktime_get_ns();

  // ---- 处理 prev：被切出 ----
  __u32 prev_pid = BPF_CORE_READ(prev, pid);
  __u32 prev_tgid = BPF_CORE_READ(prev, tgid);
  if (prev_pid) {
    // 过滤 TGID（进程维度）
    if (!conf.target_tgid || conf.target_tgid == prev_tgid) {
      long state = BPF_CORE_READ(prev, state);
      struct start_info si = {};
      si.ts_ns = now;
      si.asleep = is_sleeping(state) ? 1 : 0;

      if (!conf.sleep_only || si.asleep) {
        // 仅在需要时采集堆栈（与 BCC offcputime 一致：更偏好在 sleep
        // 时抓阻塞栈）
        si.kstack_id =
            get_kstack_id((void *)bpf_get_current_task()); // ctx 也可
        si.ustack_id = get_ustack_id((void *)bpf_get_current_task());
      } else {
        si.kstack_id = -1;
        si.ustack_id = -1;
      }

      bpf_map_update_elem(&starts, &prev_pid, &si, BPF_ANY);
    }
  }

  // ---- 处理 next：被切入，结算 offcpu ----
  __u32 next_pid = BPF_CORE_READ(next, pid);
  __u32 next_tgid = BPF_CORE_READ(next, tgid);
  if (next_pid) {
    if (!conf.target_tgid || conf.target_tgid == next_tgid) {
      struct start_info *sip = bpf_map_lookup_elem(&starts, &next_pid);
      if (sip) {
        __u64 delta = now - sip->ts_ns;
        if (delta >= conf.threshold_ns) {
          struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
          if (e) {
            e->pid = next_pid;
            e->tgid = next_tgid;
            e->cpu = bpf_get_smp_processor_id();
            e->delta_ns = delta;
            e->kstack_id = sip->kstack_id;
            e->ustack_id = sip->ustack_id;
            e->asleep = sip->asleep;
            bpf_core_read_str(&e->comm, sizeof(e->comm), next->comm);
            bpf_ringbuf_submit(e, 0);
          }
        }
        bpf_map_delete_elem(&starts, &next_pid);
      }
    }
  }

  return 0;
}
