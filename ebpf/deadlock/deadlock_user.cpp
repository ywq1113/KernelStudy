// deadlock_user.c
// 构建 & 运行：见下方 Makefile/步骤

#include "deadlock.skel.h" // 由 bpftool gen skeleton 生成
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t stop;
static void on_sigint(int sig) {
  (void)sig;
  stop = 1;
}

struct edge_t {
  __u32 pid;
  __u64 mutex;
};
struct event_t {
  __u32 root_pid;
  __u32 tgid;
  __s32 depth;
  char comm[16];
  struct edge_t chain[7]; // MAX_HOPS+1（与 bpf 一致）
};

static int on_rb_event(void *ctx, void *data, size_t len) {
  (void)ctx;
  if (len < sizeof(struct event_t))
    return 0;
  const struct event_t *e = data;

  fprintf(stdout, "\n[DEADLOCK?] tgid=%u root_tid=%u comm=%s\n", e->tgid,
          e->root_pid, e->comm);

  // 打印链路： T0(wait M0)->T1(wait M1)->...->T0
  fprintf(stdout, " chain: T%u", e->root_pid);
  for (int i = 0; i < e->depth; i++) {
    fprintf(stdout, " --wait(0x%llx)--> T%u",
            (unsigned long long)e->chain[i].mutex, e->chain[i].pid);
  }
  // 若闭环，最后一个应回到 root_tid
  if (e->depth > 0 && e->chain[e->depth - 1].pid == e->root_pid)
    fprintf(stdout, " <== CYCLE\n");
  else
    fprintf(stdout, "\n");
  fflush(stdout);
  return 0;
}

static const char *guess_pthread_path(void) {
  // 尝试常见路径（也可通过命令行传入）
  const char *candidates[] = {
      "/lib/x86_64-linux-gnu/libpthread.so.0",
      "/usr/lib/x86_64-linux-gnu/libpthread.so.0",
      "/lib64/libpthread.so.0",
      "/lib/libpthread.so.0",
      NULL,
  };
  for (int i = 0; candidates[i]; i++) {
    if (access(candidates[i], R_OK) == 0)
      return candidates[i];
  }
  return NULL;
}

// deadlock_user.c
int main(int argc, char **argv) {
  const char *pthread_path = NULL;
  int opt;
  pid_t target_pid = -1;

  while ((opt = getopt(argc, argv, "p:l:")) != -1) {
    switch (opt) {
    case 'p':
      target_pid = (pid_t)atoi(optarg); // 仅跟踪此 TGID
      break;
    case 'l':
      pthread_path = optarg; // 指定 libpthread 路径
      break;
    default:
      fprintf(stderr, "Usage: %s [-p tgid] [-l /path/to/libpthread.so.0]\n",
              argv[0]);
      return 1;
    }
  }

  if (!pthread_path)
    pthread_path = guess_pthread_path();

  if (!pthread_path) {
    fprintf(stderr,
            "Failed to find libpthread.so.0; use -l to specify path.\n");
    return 1;
  }

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  libbpf_set_print(libbpf_set_print_fn_t(NULL)); // 静默 libbpf 日志（按需）
  signal(SIGINT, on_sigint);

  struct deadlock_bpf *skel = deadlock_bpf__open();
  if (!skel) {
    perror("open skel");
    return 1;
  }

  if (target_pid > 0)
    skel->rodata->target_tgid = (unsigned)target_pid;

  int err = deadlock_bpf__load(skel);
  if (err) {
    fprintf(stderr, "load skel failed: %d\n", err);
    deadlock_bpf__destroy(skel);
    return 1;
  }

  // 通过 func_name 绑定 uprobes/uretprobes（需要较新
  // libbpf；老版本可手动解析符号偏移）
  struct bpf_link *link_lock_enter = NULL, *link_lock_exit = NULL,
                  *link_unlock_enter = NULL;

  struct bpf_uprobe_opts uopts = {};
  uopts.sz = sizeof(uopts);
  uopts.retprobe = 0;
  uopts.pid = -1; // -1: 所有进程；若只跟踪某进程，也可传入其 tgid
  uopts.func_name = "pthread_mutex_lock";
  uopts.path = pthread_path;

  link_lock_enter =
      bpf_program__attach_uprobe_opts(skel->progs.lock_enter, &uopts);
  if (!link_lock_enter) {
    perror("attach lock enter");
    goto cleanup;
  }

  uopts.retprobe = 1; // uretprobe
  link_lock_exit =
      bpf_program__attach_uprobe_opts(skel->progs.lock_exit, &uopts);
  if (!link_lock_exit) {
    perror("attach lock exit");
    goto cleanup;
  }

  uopts.retprobe = 0; // unlock 入口
  uopts.func_name = "pthread_mutex_unlock";
  link_unlock_enter =
      bpf_program__attach_uprobe_opts(skel->progs.unlock_enter, &uopts);
  if (!link_unlock_enter) {
    perror("attach unlock enter");
    goto cleanup;
  }

  // ring buffer 读取
  struct ring_buffer *rb =
      ring_buffer__new(bpf_map__fd(skel->maps.rb), on_rb_event, NULL, NULL);
  if (!rb) {
    perror("ring_buffer__new");
    goto cleanup;
  }

  printf("deadlock (CO-RE + ringbuf) running. libpthread=%s %s\n", pthread_path,
         target_pid > 0 ? "[filter by tgid]" : "[all processes]");

  while (!stop) {
    int r = ring_buffer__poll(rb, 200 /*ms*/);
    if (r == -EINTR)
      break;
  }

  ring_buffer__free(rb);

cleanup:
  bpf_link__destroy(link_unlock_enter);
  bpf_link__destroy(link_lock_exit);
  bpf_link__destroy(link_lock_enter);

  deadlock_bpf__destroy(skel);
  return 0;
}