#include "dobby_internal.h"

#define NOMINMAX
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>


#ifdef _WIN64
#define GetSyscallFunction GetSyscallFunction_x64
#else 
#define GetSyscallFunction GetSyscallFunction_x86
#endif // _WIN64

using namespace zz;

typedef NTSTATUS(NTAPI *NtProtectVirtualMemoryFunc)(
  HANDLE ProcessHandle, 
  PVOID *BaseAddress, 
  PSIZE_T NumberOfBytesToProtect, 
  ULONG NewAccessProtection, 
  PULONG OldAccessProtection
);
static NtProtectVirtualMemoryFunc NtProtectVirtualMemory = nullptr;

template <typename T> 
inline T CastRVATo(void *base, uint32_t offset) {
  return reinterpret_cast<T>((uint8_t *)(base) + offset);
}

DWORD RvaToFileOffset(void* base, DWORD rva) {
  PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
  PIMAGE_NT_HEADERS ntHeaders = CastRVATo<PIMAGE_NT_HEADERS>(base, dosHeader->e_lfanew);
  PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

  for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++) {
    if (rva >= sectionHeader->VirtualAddress &&
        rva < (sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize)) {
      return (rva - sectionHeader->VirtualAddress) + sectionHeader->PointerToRawData;
    }
  }
  return 0;
}

template <typename T> 
inline T CastFileRVATo(void *base, uint32_t rva) {
  return reinterpret_cast<T>((uint8_t *)(base) + RvaToFileOffset(base, rva));
}


uint32_t GetSyscallNumber() {
#ifdef _WIN64
  PPEB peb = (PPEB)__readgsqword(0x60);
#else
  PPEB peb = (PPEB)__readfsdword(0x30);
#endif

  if (!peb) {
    ERROR_LOG("Failed to get PEB");
    return 0;
  }

  PEB_LDR_DATA *ldr = peb->Ldr;
  if (!ldr) {
    ERROR_LOG("Failed to get LDR");
    return 0;
  }

  PIMAGE_EXPORT_DIRECTORY exportDir = nullptr;
  void *dllBase = nullptr;

  PLDR_DATA_TABLE_ENTRY ldrEntry;
  for (ldrEntry = (PLDR_DATA_TABLE_ENTRY)ldr->Reserved2[1]; 
       ldrEntry->DllBase != nullptr;
       ldrEntry = (PLDR_DATA_TABLE_ENTRY)ldrEntry->Reserved1[0]) 
  {
    UNICODE_STRING dllName = *reinterpret_cast<UNICODE_STRING *>(&ldrEntry->Reserved4);
    if (_wcsicmp(dllName.Buffer, L"ntdll.dll") == 0) {
      break;
    }
  }

  if (!ldrEntry->DllBase) {
    ERROR_LOG("Failed to find ntdll.dll");
    return 0;
  }

  std::wstring fullDllName = ldrEntry->FullDllName.Buffer;
  std::ifstream file(fullDllName, std::ios::binary);
  if (!file) {
    ERROR_LOG("Failed to open ntdll.dll");
    return 0;
  }

  std::vector<uint8_t> temp((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));

  file.close();
  dllBase = temp.data();

  // dllBase = ldrEntry->DllBase; // Some process will modify the functions in ntdll.dll when it load into memory
  PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dllBase);
  PIMAGE_NT_HEADERS ntHeaders = CastRVATo<PIMAGE_NT_HEADERS>(dllBase, dosHeader->e_lfanew);
  PIMAGE_DATA_DIRECTORY dataDir = ntHeaders->OptionalHeader.DataDirectory;
  DWORD virtualAddress = dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

  exportDir = CastFileRVATo<PIMAGE_EXPORT_DIRECTORY>(dllBase, virtualAddress);

  if (!exportDir) {
    ERROR_LOG("Failed to find export directory");
    return 0;
  }

  uint32_t numNames = exportDir->NumberOfNames;

  uint32_t *functions = CastFileRVATo<uint32_t *>(dllBase, exportDir->AddressOfFunctions);
  uint32_t *names = CastFileRVATo<uint32_t *>(dllBase, exportDir->AddressOfNames);
  uint16_t *ordinals = CastFileRVATo<uint16_t *>(dllBase, exportDir->AddressOfNameOrdinals);
  for (uint32_t i = 0; i < numNames; i++) {
    const char *funcName = CastFileRVATo<const char *>(dllBase, names[i]);
    if (std::strcmp(funcName, "NtProtectVirtualMemory") != 0)
      continue;

    uintptr_t address = CastFileRVATo<uintptr_t>(dllBase, functions[ordinals[i]]);
    for (int i = 0; i < (0x20 - 0x5); i++) {
      if (*reinterpret_cast<uint8_t *>(address + i) == 0xb8) {
        return *reinterpret_cast<uint32_t *>(address + i + 1);
      }
    }
  }

  return 0;
}

uint32_t GetSyscallNumberMem() {
#ifdef _WIN64
  PPEB peb = (PPEB)__readgsqword(0x60);
#else
  PPEB peb = (PPEB)__readfsdword(0x30);
#endif

  PEB_LDR_DATA *ldr = peb->Ldr;

  PIMAGE_EXPORT_DIRECTORY exportDir = nullptr;
  void *dllBase = nullptr;

  PLDR_DATA_TABLE_ENTRY ldrEntry;
  for (ldrEntry = (PLDR_DATA_TABLE_ENTRY)ldr->Reserved2[1]; ldrEntry->DllBase != nullptr;
       ldrEntry = (PLDR_DATA_TABLE_ENTRY)ldrEntry->Reserved1[0]) {
    dllBase = ldrEntry->DllBase;

    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dllBase);
    PIMAGE_NT_HEADERS ntHeaders = CastRVATo<PIMAGE_NT_HEADERS>(dllBase, dosHeader->e_lfanew);
    PIMAGE_DATA_DIRECTORY dataDir = ntHeaders->OptionalHeader.DataDirectory;
    DWORD virtualAddress = dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (virtualAddress == 0)
      continue;

    exportDir = CastRVATo<PIMAGE_EXPORT_DIRECTORY>(dllBase, virtualAddress);
    std::string dllName = CastRVATo<char*>(dllBase, exportDir->Name);

    if (dllName == "ntdll.dll")
      break;
  }

  if (!exportDir) {
    ERROR_LOG("Failed to find export directory");
    return 0;
  }

  uint32_t numNames = exportDir->NumberOfNames;
  uint32_t *functions = CastRVATo<uint32_t *>(dllBase, exportDir->AddressOfFunctions);
  uint32_t *names = CastRVATo<uint32_t *>(dllBase, exportDir->AddressOfNames);
  uint16_t *ordinals = CastRVATo<uint16_t *>(dllBase, exportDir->AddressOfNameOrdinals);
  for (uint32_t i = 0; i < numNames; i++) {
    const char *funcName = CastRVATo<const char *>(dllBase, names[i]);
    if (std::strcmp(funcName, "NtProtectVirtualMemory") != 0)
      continue;

    uintptr_t address = CastRVATo<uintptr_t>(dllBase, functions[ordinals[i]]);
    // syscallNum = *reinterpret_cast<uint32_t *>(address + SYSCALL_NUMBER_OFFSET);
    for (int i = 0; i < (0x20 - 0x5); i++) 
      if (*reinterpret_cast<uint8_t *>(address + i) == 0xb8) 
        return *reinterpret_cast<uint32_t *>(address + i + 1);
  }

  return 0;
}

static inline void *GetSyscallFunction_x64(uint32_t syscallNum) {
  uint8_t code[] = {
      0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // +0x00 -> mov rax, gs:[0x60]
      0x4C, 0x8B, 0xD1,                                     // +0x09 -> xmov r10, rcx
      0xB8, 0x00, 0x00, 0x00, 0x00,                         // +0x0c -> mov eax, syscallNum
      0x0f, 0x05,                                           // +0x11 -> syscall
      0xC3                                                  // +0x13 -> ret
  };

  *reinterpret_cast<uint32_t *>(code + 0xd) = syscallNum;

  void *exec = VirtualAlloc(NULL, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!exec) {
	  ERROR_LOG("Failed to allocate memory");
	  return nullptr;
  }

  memcpy(exec, code, sizeof(code));

  return exec;
}

static inline void *GetSyscallFunction_x86(uint32_t syscallNum) {
  uint8_t code[] = {
    0x64, 0x8B, 0x0D, 0xC0, 0x00, 0x00, 0x00, // +0x00 -> mov ecx, dword ptr fs:[0xC0]
    0x85, 0xC9,                               // +0x07 -> test ecx, ecx
    0x75, 0x0A,                               // +0x09 -> jne _wow64
    0xBA, 0x00, 0x00, 0x00, 0x00,             // +0x0B -> mov edx, syscallNum
    0xCD, 0x2E,                               // +0x10 -> int 0x2e
    0xC3,                                     // +0x12 -> ret
    0x33, 0xC9,                               // +0x13 -> xor ecx, ecx
    0xB8, 0x00, 0x00, 0x00, 0x00,             // +0x15 -> mov eax, syscallNum (_wow64)
    0x8D, 0x54, 0x24, 0x04,                   // +0x1A -> lea edx, [esp+0x04]
    0xFF, 0x11,                               // +0x1E -> call dword ptr [ecx]
    0xC3                                      // +0x20 -> ret
  };

  *reinterpret_cast<uint32_t *>(code + 0xc) = syscallNum;
  *reinterpret_cast<uint32_t *>(code + 0x16) = syscallNum;

  void *exec = VirtualAlloc(NULL, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!exec) {
    ERROR_LOG("Failed to allocate memory");
    return nullptr;
  }

  memcpy(exec, code, sizeof(code));
  
  return exec;
}

PUBLIC MemoryOperationError CodePatch(void *address, uint8_t *buffer, uint32_t buffer_size) {
  if (!NtProtectVirtualMemory) {
    uint32_t syscallNum = GetSyscallNumber();
    if (syscallNum == 0) {
      ERROR_LOG("Failed to get syscall number");
      return kMemoryOperationError;
    }

    void* ret = GetSyscallFunction(syscallNum);
    if (!ret) {
      ERROR_LOG("Failed to get syscall function");
      return kMemoryOperationError;
    }
    NtProtectVirtualMemory = reinterpret_cast<NtProtectVirtualMemoryFunc>(ret);
  }

  ULONG oldProtect;
  int pageSize;

  SYSTEM_INFO si;
  GetSystemInfo(&si);
  pageSize = si.dwPageSize;

  void *addressPageAlign = (void *)ALIGN(address, pageSize);

  NTSTATUS ret;
  SIZE_T regionSize = pageSize;
  ULONG newProtect = PAGE_EXECUTE_READWRITE;
  HANDLE hProc = GetCurrentProcess();
  //DWORD pid = GetCurrentProcessId();
  //HANDLE hProc = OpenProcess(PROCESS_VM_OPERATION, FALSE, pid);

  ret = NtProtectVirtualMemory(hProc, &addressPageAlign, &regionSize, newProtect, &oldProtect);
  if (ret != STATUS_SUCCESS) {
    ERROR_LOG("Error NtProtectVirtualMemory return 0x%X", ret);
    return kMemoryOperationError;
  }

  memcpy(address, buffer, buffer_size);

  ret = NtProtectVirtualMemory(hProc, &addressPageAlign, &regionSize, oldProtect, &oldProtect);
  if (ret != STATUS_SUCCESS) {
    ERROR_LOG("Error NtProtectVirtualMemory return 0x%X", ret);
    return kMemoryOperationError;
  }

  return kMemoryOperationSuccess;
}
