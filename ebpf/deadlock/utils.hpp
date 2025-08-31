// find_lib_for_pid.hpp
#pragma once
#include <optional>
#include <fstream>
#include <string>
#include <climits>
#include <unistd.h>

inline std::optional<std::string>
find_lib_for_pid(int pid, const std::string& needle) {
  std::ifstream in("/proc/" + std::to_string(pid) + "/maps");
  if (!in) return std::nullopt;

  std::string line;
  while (std::getline(in, line)) {
    // 形如: 7f2b7e0f1000-7f2b7e2f1000 r-xp 00000000 08:01 123456 /usr/lib/x86_64-linux-gnu/libpthread.so.0
    auto first_sp = line.find(' ');
    if (first_sp == std::string::npos) continue;
    auto second_sp = line.find(' ', first_sp + 1);
    if (second_sp == std::string::npos) continue;

    std::string perms = line.substr(first_sp + 1, second_sp - first_sp - 1);
    if (perms.find('x') == std::string::npos) continue;     // 只要可执行映射

    auto slash = line.find('/', second_sp + 1);
    if (slash == std::string::npos) continue;               // 无路径（如 [vdso]）跳过

    std::string path = line.substr(slash);
    if (path.find("(deleted)") != std::string::npos) continue;
    if (path.find(needle) == std::string::npos) continue;

    // 规范化真实路径
    char buf[PATH_MAX];
    if (realpath(path.c_str(), buf)) return std::string(buf);
    return path; // realpath 失败也先返回 maps 里的原样路径
  }
  return std::nullopt;
}
