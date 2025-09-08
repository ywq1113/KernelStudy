// offcpu.h
#pragma once
#include <linux/types.h>

#define TASK_COMM_LEN 16
#define MAX_STACK_DEPTH 127

struct start_info {
    __u64 ts_ns;  // 线程离开 CPU 的时刻, offcpu = now - ts_ns
    int kstack_id;  // 线程切出时采集到的 kernel stack ID，BPF_MAP_TYPE_STACK_TRACE map 的一个 key
    int ustack_id;
    __u8 asleep;   // 1: 上下文切出时处于可中断/不可中断睡眠；0: 运行态(被抢占/自愿让出)
};

struct event {
    __u32 pid;     // tid
    __u32 tgid;    // pid in userspace sense
    __u32 cpu;
    __u64 delta_ns;
    char comm[TASK_COMM_LEN];

    int kstack_id; // -EFAULT/-ENOENT 表示未采集或失败
    int ustack_id;
    __u8 asleep;   // 同上
};
