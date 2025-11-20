#include "mem_pimpl.h"
#include <TlHelp32.h>
#include <winternl.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

using t_NtReadVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, ULONG, PULONG);
using t_NtWriteVirtualMemory = NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, ULONG, PULONG);

static void* p_nt_read_syscall_stub = nullptr;
static void* p_nt_write_syscall_stub = nullptr;

namespace Memory::detail {

    uintptr_t get_export_address(HMODULE module, const char* func_name) {
        auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(module) + dos_header->e_lfanew);
        if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return 0;

        auto export_dir_entry = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        auto export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<BYTE*>(module) + export_dir_entry.VirtualAddress);

        auto names = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(module) + export_dir->AddressOfNames);
        auto ordinals = reinterpret_cast<WORD*>(reinterpret_cast<BYTE*>(module) + export_dir->AddressOfNameOrdinals);
        auto functions = reinterpret_cast<DWORD*>(reinterpret_cast<BYTE*>(module) + export_dir->AddressOfFunctions);

        for (DWORD i = 0; i < export_dir->NumberOfNames; ++i) {
            auto name = reinterpret_cast<const char*>(reinterpret_cast<BYTE*>(module) + names[i]);
            if (_stricmp(name, func_name) == 0) {
                return reinterpret_cast<uintptr_t>(reinterpret_cast<BYTE*>(module) + functions[ordinals[i]]);
            }
        }
        return 0;
    }

    void* create_syscall_stub(uintptr_t func_addr) {
        if (!func_addr) return nullptr;

        DWORD syscall_id = *reinterpret_cast<DWORD*>(func_addr + 4);
        void* stub_mem = VirtualAlloc(nullptr, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!stub_mem) return nullptr;

        unsigned char stub_code[] = {
            0x4C, 0x8B, 0xD1,             
            0xB8, 0x00, 0x00, 0x00, 0x00, 
            0x0F, 0x05,                   
            0xC3                          
        };

        *reinterpret_cast<DWORD*>(&stub_code[4]) = syscall_id;
        memcpy(stub_mem, stub_code, sizeof(stub_code));

        return stub_mem;
    }

    bool MemoryImpl::initialize_syscalls() {
        static bool initialized = false;
        if (initialized) return p_nt_read_syscall_stub && p_nt_write_syscall_stub;

        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) return false;

        uintptr_t read_addr = get_export_address(ntdll, "NtReadVirtualMemory");
        uintptr_t write_addr = get_export_address(ntdll, "NtWriteVirtualMemory");

        p_nt_read_syscall_stub = create_syscall_stub(read_addr);
        p_nt_write_syscall_stub = create_syscall_stub(write_addr);

        initialized = true;
        return p_nt_read_syscall_stub && p_nt_write_syscall_stub;
    }

    MemoryImpl::MemoryImpl(DWORD process_id, HANDLE process_handle)
        : process_id_(process_id), process_handle_(process_handle) {
    }

    MemoryImpl::~MemoryImpl() {
        if (process_handle_ && process_handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(process_handle_);
        }
    }

    std::optional<DWORD> MemoryImpl::find_process_id(std::wstring_view process_name) {
        PROCESSENTRY32W entry;
        entry.dwSize = sizeof(PROCESSENTRY32W);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return std::nullopt;

        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (process_name.compare(entry.szExeFile) == 0) {
                    CloseHandle(snapshot);
                    return entry.th32ProcessID;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
        return std::nullopt;
    }

    HANDLE MemoryImpl::open_process_handle(DWORD process_id) {
        return OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, process_id);
    }

    uintptr_t MemoryImpl::find_module_base(std::wstring_view module_name) const {
        MODULEENTRY32W entry;
        entry.dwSize = sizeof(MODULEENTRY32W);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id_);
        if (snapshot == INVALID_HANDLE_VALUE) return 0;

        if (Module32FirstW(snapshot, &entry)) {
            do {
                if (module_name.compare(entry.szModule) == 0) {
                    CloseHandle(snapshot);
                    return reinterpret_cast<uintptr_t>(entry.modBaseAddr);
                }
            } while (Module32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
        return 0;
    }

    bool MemoryImpl::read_memory(uintptr_t address, void* buffer, size_t size) const {
        if (!p_nt_read_syscall_stub) return false;
        auto nt_read = reinterpret_cast<t_NtReadVirtualMemory>(p_nt_read_syscall_stub);
        return NT_SUCCESS(nt_read(process_handle_, (PVOID)address, buffer, static_cast<ULONG>(size), nullptr));
    }

    bool MemoryImpl::write_memory(uintptr_t address, const void* buffer, size_t size) const {
        if (!p_nt_write_syscall_stub) return false;
        auto nt_write = reinterpret_cast<t_NtWriteVirtualMemory>(p_nt_write_syscall_stub);
        return NT_SUCCESS(nt_write(process_handle_, (PVOID)address, (PVOID)buffer, static_cast<ULONG>(size), nullptr));
    }
}
