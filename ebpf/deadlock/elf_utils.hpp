// elf_utils.hpp
// SPDX-License-Identifier: MIT
#pragma once
#include <elf.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

// ---------- 内部小工具 ----------

namespace elfutil {

struct ElfHandle {
  Elf *e;
  int fd;
  ElfHandle() : e(nullptr), fd(-1) {}
  ~ElfHandle() {
    if (e)
      elf_end(e);
    if (fd >= 0)
      close(fd);
  }
  ElfHandle& operator=(ElfHandle&& other) noexcept {
    if (this != &other) {
      if (e)  elf_end(e);
      if (fd >= 0) close(fd);
      e = other.e;   other.e = nullptr;
      fd = other.fd; other.fd = -1;
    }
    return *this;
  }
  ElfHandle(const ElfHandle &) = delete;
  ElfHandle &operator=(const ElfHandle &) = delete;
};

inline GElf_Ehdr get_ehdr(Elf *e) {
  GElf_Ehdr ehdr;
  if (!gelf_getehdr(e, &ehdr))
    throw std::runtime_error("gelf_getehdr failed");
  return ehdr;
}

// 计算“load bias”：取所有 PT_LOAD 段里最小的 p_vaddr
inline uint64_t calc_load_bias(Elf *e) {
  size_t nph = 0;
  if (elf_getphdrnum(e, &nph) != 0)
    return 0;
  uint64_t min_vaddr = std::numeric_limits<uint64_t>::max();
  for (size_t i = 0; i < nph; ++i) {
    GElf_Phdr phdr;
    if (!gelf_getphdr(e, i, &phdr))
      continue;
    if (phdr.p_type != PT_LOAD)
      continue;
    if (phdr.p_vaddr < min_vaddr)
      min_vaddr = phdr.p_vaddr;
  }
  if (min_vaddr == std::numeric_limits<uint64_t>::max())
    return 0;
  return min_vaddr;
}

inline bool name_matches(const char *elf_name, const char *want) {
  if (!elf_name)
    return false;
  if (std::strcmp(elf_name, want) == 0)
    return true;
  // 允许无版本名匹配带版本符号：比如 "pthread_mutex_lock" 匹配
  // "pthread_mutex_lock@@GLIBC_2.34"
  const char *at = std::strchr(elf_name, '@');
  if (at) {
    size_t n = static_cast<size_t>(at - elf_name);
    return std::strlen(want) == n && std::strncmp(elf_name, want, n) == 0;
  }
  return false;
}

// 扫描某个符号表（DYNSYM 或 SYMTAB），返回 (命中?, st_value, bind, type)
inline std::optional<std::tuple<uint64_t, unsigned char, unsigned char>>
scan_symtab(Elf *e, Elf_Scn *scn, const char *want) {
  GElf_Shdr shdr;
  if (!gelf_getshdr(scn, &shdr))
    return std::nullopt;
  if (shdr.sh_type != SHT_DYNSYM && shdr.sh_type != SHT_SYMTAB)
    return std::nullopt;

  Elf_Data *data = elf_getdata(scn, nullptr);
  if (!data)
    return std::nullopt;
  size_t count = shdr.sh_size / shdr.sh_entsize;

  // 优先选择 GLOBAL/WEAK 且已定义的函数
  std::optional<std::tuple<uint64_t, unsigned char, unsigned char>> best;

  for (size_t i = 0; i < count; ++i) {
    GElf_Sym sym;
    if (!gelf_getsym(data, (int)i, &sym))
      continue;
    unsigned char st_type = GELF_ST_TYPE(sym.st_info);
    if (st_type != STT_FUNC && st_type != STT_GNU_IFUNC)
      continue;
    if (sym.st_shndx == SHN_UNDEF)
      continue;

    const char *nm = elf_strptr(e, shdr.sh_link, sym.st_name);
    if (!name_matches(nm, want))
      continue;

    unsigned char bind = GELF_ST_BIND(sym.st_info);
    // 记录一个候选：更偏向 GLOBAL，其次 WEAK；st_value 更小的优先
    if (!best) {
      best = std::make_tuple((uint64_t)sym.st_value, bind, st_type);
    } else {
      auto [cur_val, cur_bind, cur_type] = *best;
      bool prefer = false;
      auto rank = [](unsigned char b) {
        return (b == STB_GLOBAL) ? 2 : (b == STB_WEAK ? 1 : 0);
      };
      if (rank(bind) > rank(cur_bind))
        prefer = true;
      else if (rank(bind) == rank(cur_bind) && (uint64_t)sym.st_value < cur_val)
        prefer = true;
      if (prefer)
        best = std::make_tuple((uint64_t)sym.st_value, bind, st_type);
    }
  }
  return best;
}

inline std::optional<uint64_t> find_sym_value(Elf *e, const char *want) {
  // 先 DYNSYM，再 SYMTAB
  Elf_Scn *scn = nullptr;
  std::optional<uint64_t> val;
  // 第一轮：DYNSYM
  while ((scn = elf_nextscn(e, scn)) != nullptr) {
    GElf_Shdr shdr;
    if (!gelf_getshdr(scn, &shdr))
      continue;
    if (shdr.sh_type != SHT_DYNSYM)
      continue;
    auto hit = scan_symtab(e, scn, want);
    if (hit) {
      val = std::get<0>(*hit);
      break;
    }
  }
  if (val)
    return val;
  // 第二轮：SYMTAB
  scn = nullptr;
  while ((scn = elf_nextscn(e, scn)) != nullptr) {
    GElf_Shdr shdr;
    if (!gelf_getshdr(scn, &shdr))
      continue;
    if (shdr.sh_type != SHT_SYMTAB)
      continue;
    auto hit = scan_symtab(e, scn, want);
    if (hit) {
      val = std::get<0>(*hit);
      break;
    }
  }
  return val;
}

} // namespace elfutil

// ---------- 对外 API ----------

// 返回：uprobes 需要的“相对模块基址偏移”
// 规则：
// - 共享库/PIE (ET_DYN)：返回 st_value
// - 非 PIE 可执行 (ET_EXEC)：返回 st_value - load_bias (最小 PT_LOAD.p_vaddr)
inline std::optional<size_t> find_func_offset_in_elf(const std::string &path,
                                                     const char *symname) {
  try {
    elfutil::ElfHandle h;
    if (elf_version(EV_CURRENT) == EV_NONE)
        throw std::runtime_error("elf_version failed");
    h.fd = ::open(path.c_str(), O_RDONLY);
    if (h.fd < 0)
        throw std::runtime_error("open ELF failed: " + path);
    h.e = elf_begin(h.fd, ELF_C_READ, nullptr);
    if (!h.e)
        throw std::runtime_error("elf_begin failed");
    auto eh = elfutil::get_ehdr(h.e);

    auto val_opt = elfutil::find_sym_value(h.e, symname);
    if (!val_opt)
      return std::nullopt;

    uint64_t st_value = *val_opt;

    if (eh.e_type == ET_DYN) {
      // 共享库 / PIE
      return static_cast<size_t>(st_value);
    } else if (eh.e_type == ET_EXEC) {
      // 非 PIE：把绝对 VA 减去 load_bias，得到相对模块的偏移
      uint64_t bias = elfutil::calc_load_bias(h.e);
      if (st_value < bias)
        return std::nullopt; // 不合理，保护一下
      return static_cast<size_t>(st_value - bias);
    } else {
      // 其它类型（极少见），直接返回 st_value 尝试一下
      return static_cast<size_t>(st_value);
    }
  } catch (...) {
    return std::nullopt;
  }
}
