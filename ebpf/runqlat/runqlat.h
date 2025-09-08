// runqlat.h
#pragma once

#define TASK_COMM_LEN 16
#define MAX_SLOTS 64 // log2 直方图槽位数

enum unit_e {
  UNIT_NS = 0,
  UNIT_US = 1,
  UNIT_MS = 2,
};

struct hist {
  __u64 slots[MAX_SLOTS];
} __attribute__((aligned(8)));

struct cfg {
  __u32 target_tgid;  // 0 不过滤
  __u32 target_tid;   // 0 不过滤（可选）
  __u64 threshold_ns; // 小于该延迟丢弃（降噪）
  __u8 unit;          // enum unit_e
  __u8 _pad[7];
};
