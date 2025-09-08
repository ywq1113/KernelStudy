// runqlat_user.c
#define _GNU_SOURCE
#include "runqlat.h"
#include "runqlat.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static volatile sig_atomic_t exiting;

static void on_sig(int signo) { exiting = 1; }

static const struct option long_opts[] = {
    {"pid", required_argument, NULL, 'p'},  // TGID
    {"tid", required_argument, NULL, 't'},  // TID
    {"unit", required_argument, NULL, 'u'}, // ns/us/ms
    {"min", required_argument, NULL, 'm'}, // 最小阈值（与unit无关，单位 ns）
    {"interval", required_argument, NULL, 'i'}, // 打印间隔秒
    {"duration", required_argument, NULL, 'd'}, // 总时长秒
    {0, 0, 0, 0}};

static void bump_memlock_rlimit(void) {
  struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
  if (setrlimit(RLIMIT_MEMLOCK, &r)) {
    perror("setrlimit");
    exit(1);
  }
}

static void print_banner(enum unit_e u, __u32 tgid, __u32 tid) {
  const char *ustr = (u == UNIT_NS) ? "ns" : (u == UNIT_MS) ? "ms" : "us";
  printf("runqlat (unit=%s)%s%s\n", ustr, tgid ? ", filter tgid=" : "",
         tgid ? ({
           static char buf[32];
           snprintf(buf, sizeof buf, "%u", tgid), buf;
         })
              : "");
  if (tid)
    printf("  filter tid=%u\n", tid);
}

static void print_hist_header(enum unit_e u) {
  const char *ustr = (u == UNIT_NS) ? "ns" : (u == UNIT_MS) ? "ms" : "us";
  printf("\n%12s : %-8s | %-6s\n", "range", "count", "bar");
  printf("-------------+----------+------------------------------\n");
}

static void print_histogram(int map_fd, enum unit_e u) {
  int ncpu = libbpf_num_possible_cpus();
  if (ncpu <= 0) {
    fprintf(stderr, "cpu count err\n");
    return;
  }

  __u32 key = 0;
  size_t val_sz = sizeof(struct hist);
  size_t buf_sz = val_sz * (size_t)ncpu;

  struct hist *pcpu = calloc(ncpu, val_sz);
  struct hist total = {};
  if (!pcpu) {
    perror("calloc");
    return;
  }

  if (bpf_map_lookup_elem(map_fd, &key, pcpu) != 0) {
    perror("lookup hist");
    free(pcpu);
    return;
  }
  // 累加
  for (int c = 0; c < ncpu; c++) {
    for (int i = 0; i < MAX_SLOTS; i++) {
      total.slots[i] += pcpu[c].slots[i];
    }
  }

  // 打印
  print_hist_header(u);
  __u64 grand = 0;
  for (int i = 0; i < MAX_SLOTS; i++)
    grand += total.slots[i];

  for (int i = 0; i < MAX_SLOTS; i++) {
    __u64 cnt = total.slots[i];
    if (!cnt)
      continue;
    // 区间：[2^i, 2^(i+1)) in selected unit
    unsigned long long lo = (i == 0) ? 0ull : (1ull << i);
    unsigned long long hi = (1ull << (i + 1));
    int bars = (int)(cnt * 30.0 / (grand ? grand : 1));
    if (bars < 1 && cnt)
      bars = 1;

    printf("%6llu - %-6llu : %-8llu | ", lo, hi, (unsigned long long)cnt);
    for (int b = 0; b < bars; b++)
      putchar('#');
    putchar('\n');
  }

  // 清零（下一轮间隔重新累计）
  struct hist zero = {};
  if (bpf_map_update_elem(map_fd, &key, &zero, 0) != 0) {
    perror("reset hist");
  }

  free(pcpu);
}

static void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s [-p tgid] [-t tid] [-u ns|us|ms] [-m min_ns] [-i sec] [-d "
          "sec]\n"
          "  -p,--pid     仅统计指定进程（TGID）\n"
          "  -t,--tid     仅统计指定线程（TID）\n"
          "  -u,--unit    输出单位：ns/us/ms（默认 us）\n"
          "  -m,--min     丢弃小于该延迟的样本（单位 ns，默认 0）\n"
          "  -i,--interval直方图打印间隔秒（默认 1）\n"
          "  -d,--duration运行总秒数（默认 0=持续直到 Ctrl-C）\n",
          prog);
}

int main(int argc, char **argv) {
  __u32 tgid = 0, tid = 0;
  __u64 min_ns = 0;
  enum unit_e unit = UNIT_US;
  int interval = 1, duration = 0, opt;

  while ((opt = getopt_long(argc, argv, "p:t:u:m:i:d:", long_opts, NULL)) !=
         -1) {
    switch (opt) {
    case 'p':
      tgid = strtoul(optarg, NULL, 10);
      break;
    case 't':
      tid = strtoul(optarg, NULL, 10);
      break;
    case 'u':
      if (!strcmp(optarg, "ns"))
        unit = UNIT_NS;
      else if (!strcmp(optarg, "ms"))
        unit = UNIT_MS;
      else
        unit = UNIT_US;
      break;
    case 'm':
      min_ns = strtoull(optarg, NULL, 10);
      break;
    case 'i':
      interval = atoi(optarg);
      if (interval <= 0)
        interval = 1;
      break;
    case 'd':
      duration = atoi(optarg);
      break;
    default:
      usage(argv[0]);
      return 1;
    }
  }

  bump_memlock_rlimit();
  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

  struct runqlat_bpf *skel = runqlat_bpf__open();
  if (!skel) {
    fprintf(stderr, "open skel failed\n");
    return 1;
  }

  skel->rodata->conf.target_tgid = tgid;
  skel->rodata->conf.target_tid = tid;
  skel->rodata->conf.threshold_ns = min_ns;
  skel->rodata->conf.unit = unit;

  int err = runqlat_bpf__load(skel);
  if (err) {
    fprintf(stderr, "load failed: %d\n", err);
    goto cleanup;
  }

  err = runqlat_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "attach failed: %d\n", err);
    goto cleanup;
  }

  signal(SIGINT, on_sig);
  signal(SIGTERM, on_sig);

  print_banner(unit, tgid, tid);

  time_t end_ts = duration > 0 ? time(NULL) + duration : 0;
  while (!exiting) {
    sleep(interval);
    print_histogram(bpf_map__fd(skel->maps.hists), unit);
    if (duration > 0 && time(NULL) >= end_ts)
      break;
  }

cleanup:
  runqlat_bpf__destroy(skel);
  return 0;
}
