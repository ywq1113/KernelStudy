// deadlock.bpf.c
// CO-RE + ring buffer 版用户态死锁检测（pthread mutex）
#include "../vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// 可通过用户态修改：仅跟踪此 tgid（进程）；为 0 表示不过滤
const volatile __u32 target_tgid = 0;

// 检测深度上限（影响栈大小/验证器展开）
#define MAX_HOPS 6

struct edge_t {
  __u32 pid;   // 线程（轻量级 pid/TID）
  __u64 mutex; // 互斥量地址
};

struct event_t {
  __u32 root_pid; // 起始线程（触发检测的线程）
  __u32 tgid;     // 进程 id
  __s32 depth;    // 链路长度（<= MAX_HOPS+1）
  char comm[16];
  struct edge_t chain[MAX_HOPS + 1]; // Recorder the chain of edges, MAX_HOPS+1 means the last edge can point back to the root
};

// key 互斥量 -> value 持有该互斥量的线程（TID）
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, __u64);
  __type(value, __u32);
} mutex_owner SEC(".maps");

// key 线程（TID）-> value 等待获取的互斥量地址
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, __u32);
  __type(value, __u64);
} thread_wait SEC(".maps");

// ring buffer：向用户态上报疑似死锁
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 22); // 4MB，按需调整
} rb SEC(".maps");

static __always_inline int filter_tgid(void) {
  if (!target_tgid)
    return 1;
  __u64 id = bpf_get_current_pid_tgid();
  __u32 tgid = id >> 32;
  return tgid == target_tgid;
}

static __always_inline void try_detect_deadlock(__u32 start_pid, __u32 tgid,
                                                __u64 first_mutex) {
  // 在栈上暂存链路，避免过早 reserve ringbuf
  struct event_t ev = {};
  ev.root_pid = start_pid;
  ev.tgid = tgid;
  // 把当前正在运行的 task（即当前线程）的 comm 拷贝出来，默认是进程名
  bpf_get_current_comm(&ev.comm, sizeof(ev.comm));

  __u64 cur_mutex = first_mutex;
  __u32 cur_owner = 0;

// 通过 #pragma unroll 展开循环，避免 verifier 报错
#pragma unroll
  for (int i = 0; i < MAX_HOPS + 1; i++) {
    // 在内核里查某个 BPF map 里是否有对应 key 的值，并返回指向 value 的指针
    // 这里查的就是 cur_mutex 这个锁的持有者
    __u32 *owner = bpf_map_lookup_elem(&mutex_owner, &cur_mutex);

    if (!owner)
      return; // 无人持有，链路断开

    cur_owner = *owner;
    ev.chain[i].pid = cur_owner;
    ev.chain[i].mutex = cur_mutex;
    ev.depth = i + 1;

    // 检测循环：回到起点线程 → 死锁
    if (cur_owner == start_pid) {
      // 提交事件
      struct event_t *out = bpf_ringbuf_reserve(&rb, sizeof(ev), 0);
      if (!out)
        return;
      *out = ev;
      bpf_ringbuf_submit(out, 0);
      return;
    }

    // 继续沿链查找：查看 cur_owner 是否也在等待某个互斥量
    __u64 *next_mutex = bpf_map_lookup_elem(&thread_wait, &cur_owner);
    if (!next_mutex)
      return; // 对方未等待，链路断开
    cur_mutex = *next_mutex;
  }

  // 走满 MAX_HOPS 仍未闭环，则放弃（避免无限循环）
  return;
}

// ---- uprobes/uretprobes: pthread_mutex_lock/unlock ----

// 进入 pthread_mutex_lock：记录“当前线程等待的互斥量”，并尝试检测死锁
SEC("uprobe/pthread_mutex_lock")
int BPF_KPROBE(lock_enter, void *mutex) {
  if (!filter_tgid())
    return 0;
  __u64 id = bpf_get_current_pid_tgid();
  __u32 pid = (__u32)id;
  __u32 tgid = id >> 32;
  __u64 m = (__u64)mutex;

  // 记录等待关系
  bpf_map_update_elem(&thread_wait, &pid, &m, BPF_ANY);

  // 只有在已知该互斥量存在持有者时才有机会形成环
  __u32 *owner = bpf_map_lookup_elem(&mutex_owner, &m);
  if (owner) {
    // 从当前线程出发沿“等待→持有→等待→...”链检查有界环
    try_detect_deadlock(pid, tgid, m);
  }
  return 0;
}

// pthread_mutex_lock 返回：成功则建立“互斥量 →
// 当前线程”的持有关系，并清理等待标记
SEC("uretprobe/pthread_mutex_lock")
int BPF_KRETPROBE(lock_exit) {
  if (!filter_tgid())
    return 0;

  __s64 ret = PT_REGS_RC(ctx); // 0 表示成功
  __u64 id = bpf_get_current_pid_tgid();
  __u32 pid = (__u32)id;

  __u64 *pm = bpf_map_lookup_elem(&thread_wait, &pid);
  if (!pm)
    return 0; // 未记录等待，可能是 trylock 或其他路径

  if (ret == 0) {
    // 建立持有关系
    __u64 m = *pm;
    bpf_map_update_elem(&mutex_owner, &m, &pid, BPF_ANY);
  }

  // 无论成功与否，退出时移除等待标记
  bpf_map_delete_elem(&thread_wait, &pid);
  return 0;
}

// 进入 pthread_mutex_unlock：移除“互斥量 →
// 持有线程”的关系（仅限自己持有的情况）
SEC("uprobe/pthread_mutex_unlock")
int BPF_KPROBE(unlock_enter, void *mutex) {
  if (!filter_tgid())
    return 0;
  __u64 id = bpf_get_current_pid_tgid();
  __u32 pid = (__u32)id;
  __u64 m = (__u64)mutex;

  __u32 *owner = bpf_map_lookup_elem(&mutex_owner, &m);
  if (owner && *owner == pid) {
    bpf_map_delete_elem(&mutex_owner, &m);
  }
  return 0;
}