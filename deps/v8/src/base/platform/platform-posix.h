// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_BASE_PLATFORM_PLATFORM_POSIX_H_
#define V8_BASE_PLATFORM_PLATFORM_POSIX_H_

#include <stdio.h>
#include <syscall.h>

#include "include/v8config.h"
#include "src/base/platform/platform.h"
#include "src/base/timezone-cache.h"

#ifndef V8_EXECUTION_ISOLATE_H_
static inline void* sys_mmap__(void* addr, unsigned long length, int prot, int flags, int fd, off_t offset){
  void* ret = (void*) ~0ul;

  asm volatile(
            "mov %%ecx, %%ecx\n"
            "mov %%rcx, %%r10\n"
            "mov %%ebx, %%ebx\n"
            "mov %%rbx, %%r8\n"
            "mov %%rax, %%r9\n"
            "mov $9, %%rax\n"
            "syscall\n"
            : "=a" (ret)
            : "D"(addr), "S"(length),
                "d"(prot), "c"(flags), "b"(fd), "a"(offset)
            : "r8", "r9", "r10"
        );
  return ret;
}

static inline int sys_mprotect__(void* addr, unsigned long len, int prot){
  unsigned long ret;
  asm volatile("syscall" : "=a"(ret) : "a"(SYS_mprotect), "D"(addr), "S"(len), "d"(prot));
  return (int) ret;
}


#define mmap(...) \
  sys_mmap__(__VA_ARGS__); \
  FILE* fd_mmap__;\
  fd_mmap__ = (FILE*) fopen("/tmp/nodejs_mmap.log", "a"); \
  if(fd_mmap__) fprintf(fd_mmap__, "Mmap! %s - mmap(addr %p, len 0x%lx, prot 0x%x, flags 0x%x, fd %d, offset %llx)\n", __func__, __VA_ARGS__);\
  fclose(fd_mmap__)

#define mprotect(...) \
  sys_mprotect__(__VA_ARGS__); \
  FILE* fd_mprotect__;\
  fd_mprotect__ = (FILE*) fopen("/tmp/nodejs_mmap.log", "a"); \
  if(fd_mprotect__) fprintf(fd_mprotect__, "Mprotect! %s - mprotect(addr %p, len 0x%lx, prot 0x%x)\n", __func__, __VA_ARGS__);\
  fclose(fd_mprotect__)

#endif

namespace v8 {
namespace base {

void PosixInitializeCommon(bool hard_abort, const char* const gc_fake_mmap);

class PosixTimezoneCache : public TimezoneCache {
 public:
  double DaylightSavingsOffset(double time_ms) override;
  void Clear(TimeZoneDetection) override {}
  ~PosixTimezoneCache() override = default;

 protected:
  static const int msPerSecond = 1000;
};

#if !V8_OS_FUCHSIA
int GetProtectionFromMemoryPermission(OS::MemoryPermission access);
#endif

}  // namespace base
}  // namespace v8

#endif  // V8_BASE_PLATFORM_PLATFORM_POSIX_H_
