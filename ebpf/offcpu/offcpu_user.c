// offcpu_user.c
#define _GNU_SOURCE
#include "offcpu.h"
#include "offcpu.skel.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

static volatile sig_atomic_t exiting;

static void on_sigint(int signo) { exiting = 1; }

static const struct option long_opts[] = {
    {"threshold", required_argument, NULL, 't'}, // 毫秒
    {"pid", required_argument, NULL, 'p'},       // 进程 TGID 过滤
    {"sleep", no_argument, NULL, 'S'},           // 仅 sleep
    {"kernel", no_argument, NULL, 'k'},          // 采集内核栈
    {"user", no_argument, NULL, 'u'},            // 采集用户栈
    {"duration", required_argument, NULL, 'd'},  // 运行秒数
    {0, 0, 0, 0}};

static int lookup_stack(int map_fd, int stack_id, __u64 *buf, int max_depth) {
  if (stack_id < 0)
    return 0;
  __u32 key = stack_id;
  return bpf_map_lookup_elem(map_fd, &key, buf);
}

static int handle_event(void *ctx, void *data, size_t size) {
  const struct event *e = data;
  printf("[%s] tgid=%u tid=%u cpu=%u offcpu=%.3f ms%s\n", e->comm, e->tgid,
         e->pid, e->cpu, (double)e->delta_ns / 1e6,
         e->asleep ? " (sleep)" : "");

  int stacks_fd = *(int *)ctx;
  __u64 pcs[MAX_STACK_DEPTH];

  if (e->kstack_id >= 0) {
    if (!lookup_stack(stacks_fd, e->kstack_id, pcs, MAX_STACK_DEPTH)) {
      printf("  kstack:\n");
      for (int i = 0; i < MAX_STACK_DEPTH && pcs[i]; i++)
        printf("    [<%p>] %p\n", (void *)pcs[i], (void *)pcs[i]);
    } else {
      printf("  kstack: <lookup failed>\n");
    }
  }
  if (e->ustack_id >= 0) {
    if (!lookup_stack(stacks_fd, e->ustack_id, pcs, MAX_STACK_DEPTH)) {
      printf("  ustack:\n");
      for (int i = 0; i < MAX_STACK_DEPTH && pcs[i]; i++)
        printf("    [<%p>] %p\n", (void *)pcs[i], (void *)pcs[i]);
    } else {
      printf("  ustack: <lookup failed>\n");
    }
  }
  return 0;
}

static void bump_memlock_rlimit(void) {
  struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
  if (setrlimit(RLIMIT_MEMLOCK, &r)) {
    perror("setrlimit(RLIMIT_MEMLOCK)");
    exit(1);
  }
}

static void usage(const char *prog) {
  fprintf(
      stderr,
      "Usage: %s [-t ms] [-p tgid] [-S] [-k] [-u] [-d sec]\n"
      "  -t, --threshold  最小时长(毫秒)，默认 10\n"
      "  -p, --pid        仅统计指定 TGID 进程\n"
      "  -S, --sleep      仅统计 sleep 段（prev->state != 0）\n"
      "  -k, --kernel     采集内核栈\n"
      "  -u, --user       采集用户栈（可能需要较低的 perf_event_paranoid）\n"
      "  -d, --duration   运行秒数，默认无限直到 Ctrl-C\n",
      prog);
}

int main(int argc, char **argv) {
  const char *prog = argv[0];
  int err, opt;
  int duration = 0;
  __u64 threshold_ms = 10;
  __u32 target_tgid = 0;
  __u8 sleep_only = 0, cap_k = 1, cap_u = 0; // 默认采 kernel 栈

  while ((opt = getopt_long(argc, argv, "t:p:Skud:", long_opts, NULL)) != -1) {
    switch (opt) {
    case 't':
      threshold_ms = strtoull(optarg, NULL, 10);
      break;
    case 'p':
      target_tgid = strtoul(optarg, NULL, 10);
      break;
    case 'S':
      sleep_only = 1;
      break;
    case 'k':
      cap_k = 1;
      break;
    case 'u':
      cap_u = 1;
      break;
    case 'd':
      duration = atoi(optarg);
      break;
    default:
      usage(prog);
      return 1;
    }
  }

  bump_memlock_rlimit();
  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

  struct offcpu_bpf *skel = offcpu_bpf__open();
  if (!skel) {
    fprintf(stderr, "open skel failed\n");
    return 1;
  }

  // 配置 rodata
  skel->rodata->threshold_ns = threshold_ms * 1000000ULL;
  skel->rodata->target_tgid = target_tgid;
  skel->rodata->sleep_only = sleep_only;
  skel->rodata->capture_kernel = cap_k;
  skel->rodata->capture_user = cap_u;

  if ((err = offcpu_bpf__load(skel))) {
    fprintf(stderr, "load skel failed: %d\n", err);
    goto cleanup;
  }
  if ((err = offcpu_bpf__attach(skel))) {
    fprintf(stderr, "attach failed: %d\n", err);
    goto cleanup;
  }

  int stacks_fd = bpf_map__fd(skel->maps.stacks);
  struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),
                                            handle_event, &stacks_fd, NULL);
  if (!rb) {
    fprintf(stderr, "ring_buffer__new failed\n");
    goto cleanup;
  }

  signal(SIGINT, on_sigint);
  signal(SIGTERM, on_sigint);

  printf("Running... threshold=%llums target_tgid=%u sleep_only=%u kernel=%u "
         "user=%u\n",
         (unsigned long long)threshold_ms, target_tgid, sleep_only, cap_k,
         cap_u);

  time_t end_ts = duration > 0 ? time(NULL) + duration : 0;
  while (!exiting) {
    err = ring_buffer__poll(rb, 200 /* ms */);
    if (err == -EINTR)
      break;
    if (err < 0) {
      fprintf(stderr, "ring_buffer__poll: %d\n", err);
      break;
    }
    if (duration > 0 && time(NULL) >= end_ts)
      break;
  }

cleanup:
  ring_buffer__free(rb);
  offcpu_bpf__destroy(skel);
  return err != 0;
}
