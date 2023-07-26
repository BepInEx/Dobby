#include "dobby_internal.h"

#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>

using namespace zz;


typedef NTSTATUS(NTAPI* NtProtectVirtualMemoryFunc)(
    HANDLE ProcessHandle, 
    PVOID *BaseAddress,                                        
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
);

PUBLIC MemoryOperationError CodePatchNt(void *address, uint8_t *buffer, uint32_t buffer_size) {
  ULONG oldProtect;
  int pageSize;

  SYSTEM_INFO si;
  GetSystemInfo(&si);
  pageSize = si.dwPageSize;

  void *addressPageAlign = (void *)ALIGN(address, pageSize);

  HMODULE ntdllModule = GetModuleHandle("ntdll.dll");
  if (ntdllModule == nullptr) {
    ERROR_LOG("Error failed to get ntdll.dll");
    return kMemoryOperationError;
  }
 
  NtProtectVirtualMemoryFunc NtProtectVirtualMemory = 
      (NtProtectVirtualMemoryFunc) GetProcAddress(ntdllModule, "NtProtectVirtualMemory");
  if (NtProtectVirtualMemory == nullptr) {
    ERROR_LOG("Error failed to get address of NtProtectVirtualMemory");
    return kMemoryOperationError;
  }

  NTSTATUS ret;
  SIZE_T regionSize = pageSize;
  ULONG newProtect = PAGE_EXECUTE_READWRITE;
  HANDLE hp = GetCurrentProcess();

  ret = NtProtectVirtualMemory(hp, &addressPageAlign, &regionSize, newProtect, &oldProtect);
  if (ret != STATUS_SUCCESS) {
    ERROR_LOG("Error NtProtectVirtualMemory return 0x%X", ret);
    return kMemoryOperationError;
  }

  memcpy(address, buffer, buffer_size);

  ret = NtProtectVirtualMemory(hp, &addressPageAlign, &regionSize, oldProtect, &oldProtect);
  if (ret != STATUS_SUCCESS) {
    ERROR_LOG("Error NtProtectVirtualMemory return 0x%X", ret);
    return kMemoryOperationError;
  }

  return kMemoryOperationSuccess;
}

PUBLIC MemoryOperationError CodePatchEx(void *address, uint8_t *buffer, uint32_t buffer_size) {
  DWORD oldProtect;
  int pageSize;

  SYSTEM_INFO si;
  GetSystemInfo(&si);
  pageSize = si.dwPageSize;

  void *addressPageAlign = (void *)ALIGN(address, pageSize);

  DWORD pid = GetCurrentProcessId();
  HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION, FALSE, pid);

  if (!VirtualProtectEx(hProcess, addressPageAlign, pageSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
    DWORD err = GetLastError();
    ERROR_LOG("VirtualProtectEx failed with error coed: 0x%X", err);
    return kMemoryOperationError;
  }

  memcpy(address, buffer, buffer_size);

  if (!VirtualProtectEx(hProcess, addressPageAlign, pageSize, oldProtect, &oldProtect)) {
    DWORD err = GetLastError();
    ERROR_LOG("VirtualProtectEx failed with error coed: 0x%X", err);
    return kMemoryOperationError;
  }

  return kMemoryOperationSuccess;
}

PUBLIC MemoryOperationError CodePatchStd(void *address, uint8_t *buffer, uint32_t buffer_size) {
  DWORD oldProtect;
  int pageSize;

  // Get page size
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  pageSize = si.dwPageSize;

  void *addressPageAlign = (void *)ALIGN(address, pageSize);

  if (!VirtualProtect(addressPageAlign, pageSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
    DWORD err = GetLastError();
	ERROR_LOG("VirtualProtect failed with error coed: 0x%X", err);
	return kMemoryOperationError;
  }
    return kMemoryOperationError;

  memcpy(address, buffer, buffer_size);

  if (!VirtualProtect(addressPageAlign, pageSize, oldProtect, &oldProtect)) {
    DWORD err = GetLastError();
    ERROR_LOG("VirtualProtect failed with error coed: 0x%X", err);
    return kMemoryOperationError;
  }
    return kMemoryOperationError;

  return kMemoryOperationSuccess;
}

PUBLIC MemoryOperationError CodePatch(void *address, uint8_t *buffer, uint32_t buffer_size) {
  MemoryOperationError ret = CodePatchStd(address, buffer, buffer_size);

  // If standard method fails, try using NtProtectVirtualMemory
  if (ret != kMemoryOperationSuccess) {
    DLOG(0, "[CodePath] patch %p with VirtualProtect failed, try to patch with NtProtectVirtualMemory", address);
    ret = CodePatchNt(address, buffer, buffer_size);

    // If NtProtectVirtualMemory also fails, try using VirtualProtectEx
    if (ret != kMemoryOperationSuccess) {
      DLOG(0, "[CodePath] patch %p with NtProtectVirtualMemory failed, try to patch with VirtualProtectEx", address);
      ret = CodePatchEx(address, buffer, buffer_size);
    }
  }

  return ret;
}
