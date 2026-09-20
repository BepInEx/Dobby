// Tests emitted destinations, without executing relocated code or installing hooks.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif
#include "InstructionRelocation/InstructionRelocation.h"

int main() {
#ifdef _WIN32
  const size_t page_size = 4096;
  uint8_t *page = (uint8_t *)VirtualAlloc(nullptr, page_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!page) return 2;
#else
  const long system_page_size = sysconf(_SC_PAGESIZE);
  if (system_page_size < 1024) return 2; // Fixed offsets below require at least 1 KiB.
  const size_t page_size = (size_t)system_page_size;
  uint8_t *page = (uint8_t *)mmap(nullptr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) return 2;
#endif
  const int offsets[] = {-128, -8, 0, 1, 127};
  int failures = 0, cases = 0;
  // Both relocation directions; every short Jcc opcode; external forward/backward targets.
  for (int direction = 0; direction < 2; ++direction) {
    for (int opcode = 0x70; opcode <= 0x7f; ++opcode) {
      for (int offset : offsets) {
        uint8_t *input = page + (direction ? 512 : 256);
        uint8_t *output = page + (direction ? 256 : 512);
        const uint8_t source[] = {(uint8_t)opcode, (uint8_t)(int8_t)offset};
        AssemblyCodeChunk origin, relocated;
        origin.init_region_range((addr_t)input, sizeof(source));
        relocated.init_region_range((addr_t)output, 64);
        GenRelocateCodeAndBranch((void *)source, &origin, &relocated);
        int32_t displacement = 0;
        memcpy(&displacement, output + 2, sizeof(displacement));
        const intptr_t actual = (intptr_t)output + 6 + displacement;
        const intptr_t expected = (intptr_t)input + 2 + offset;
        ++cases;
        if (output[0] != 0x0f || output[1] != (0x80 | (opcode & 0x0f)) || actual != expected) {
          ++failures;
          if (failures < 4)
            fprintf(stderr, "Jcc 0x%x rel8=%d: destination delta=%lld\n", opcode, offset,
                    (long long)(actual - expected));
        }
      }
    }
  }
#ifdef _WIN32
  VirtualFree(page, 0, MEM_RELEASE);
#else
  munmap(page, page_size);
#endif
  printf("short Jcc relocation: cases=%d failures=%d\n", cases, failures);
  return failures ? 1 : 0;
}
