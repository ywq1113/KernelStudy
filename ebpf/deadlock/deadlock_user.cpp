// deadlock_user.c
// 构建 & 运行：见下方 Makefile/步骤

#include "deadlock.skel.h" // 由 bpftool gen skeleton 生成
#include "elf_utils.hpp"
#include "utils.hpp"
#include <bpf/libbpf.h>
#include <errno.h>
#include <memory>
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
  const struct event_t *e = static_cast<const event_t *>(data);

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

static int libbpf_log_cb(enum libbpf_print_level level, const char *fmt,
                         va_list args) {
  if (level == LIBBPF_DEBUG)
    return 0;                         // 丢弃 Debug
  return vfprintf(stderr, fmt, args); // 打印 Info/Warning/Error
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

  auto libpath = find_lib_for_pid(target_pid, "libpthread");
  if (!libpath)
    libpath =
        find_lib_for_pid(target_pid, "libc"); // glibc 2.34 后 pthread 并入 libc

  if (!libpath) {
    fprintf(stderr,
            "Failed to find libpthread.so.0; use -l to specify path.\n");
    return 1;
  }

  pthread_path = libpath->c_str();
  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  libbpf_set_print(libbpf_log_cb); // 静默 libbpf 日志（按需）

  signal(SIGINT, on_sigint);

  auto skel_ptr =
      std::unique_ptr<deadlock_bpf, decltype(&deadlock_bpf__destroy)>(
          nullptr, deadlock_bpf__destroy);
  skel_ptr.reset(deadlock_bpf__open());
  if (!skel_ptr) {
    perror("open skel");
    return 1;
  }

  int err = deadlock_bpf__load(skel_ptr.get());
  if (err) {
    fprintf(stderr, "load skel failed: %d\n", err);
    return 1;
  }

  // 解析偏移
  auto off_lock_opt =
      find_func_offset_in_elf(pthread_path, "pthread_mutex_lock");
  auto off_unlock_opt =
      find_func_offset_in_elf(pthread_path, "pthread_mutex_unlock");
  if (!off_lock_opt || !off_unlock_opt) {
    fprintf(stderr, "ELF: not found pthread symbols in %s\n", pthread_path);
    return 1;
  }
  size_t off_lock = *off_lock_opt;
  size_t off_unlock = *off_unlock_opt;

  pid_t target = target_pid; // 或 -1 做系统范围
  const char *bin = pthread_path;

  LIBBPF_OPTS(bpf_uprobe_opts, enter_opts, .retprobe = false, );

  bpf_link *link_lock_enter = bpf_program__attach_uprobe_opts(
      skel_ptr->progs.lock_enter, target, bin, off_lock, &enter_opts);
  if (!link_lock_enter || libbpf_get_error(link_lock_enter)) {
    std::fprintf(stderr, "attach lock_enter failed: %s\n",
                 strerror(-libbpf_get_error(link_lock_enter)));
    return 1;
  }

  LIBBPF_OPTS(bpf_uprobe_opts, exit_opts, .retprobe = true, );
  bpf_link *link_lock_exit = bpf_program__attach_uprobe_opts(
      skel_ptr->progs.lock_exit, target, bin, off_lock, &exit_opts);
  if (!link_lock_exit || libbpf_get_error(link_lock_exit)) {
    std::fprintf(stderr, "attach lock_ret failed: %s\n",
                 strerror(-libbpf_get_error(link_lock_exit)));
    return 1;
  }

  LIBBPF_OPTS(bpf_uprobe_opts, unlock_opts, .retprobe = false, );
  bpf_link *link_unlock_enter = bpf_program__attach_uprobe_opts(
      skel_ptr->progs.unlock_enter, target, bin, off_unlock, &unlock_opts);
  if (!link_unlock_enter || libbpf_get_error(link_unlock_enter)) {
    std::fprintf(stderr, "attach unlock_enter failed: %s\n",
                 strerror(-libbpf_get_error(link_unlock_enter)));
    return 1;
  }

  // ring buffer 读取
  auto rb_ptr = std::unique_ptr<ring_buffer, decltype(&ring_buffer__free)>(
      nullptr, ring_buffer__free);
  rb_ptr.reset(ring_buffer__new(bpf_map__fd(skel_ptr->maps.rb), on_rb_event,
                                NULL, NULL));
  if (!rb_ptr) {
    std::fprintf(stderr, "rb new fail\n");
    return 1;
  }

  printf("deadlock (CO-RE + ringbuf) running. libpthread=%s %s\n", pthread_path,
         target_pid > 0 ? "[filter by tgid]" : "[all processes]");

  while (!stop) {
    int r = ring_buffer__poll(rb_ptr.get(), 200 /*ms*/);
    if (r == -EINTR)
      break;
  }

  return 0;
}