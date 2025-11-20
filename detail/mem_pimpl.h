#pragma once
#include <Windows.h>
#include <string_view>
#include <cstdint>
#include <optional>

namespace Memory::detail {

    class MemoryImpl {
    public:
        MemoryImpl(DWORD process_id, HANDLE process_handle);
        ~MemoryImpl();

        static bool initialize_syscalls();

        [[nodiscard]] uintptr_t find_module_base(std::wstring_view module_name) const;

        bool read_memory(uintptr_t address, void* buffer, size_t size) const;
        bool write_memory(uintptr_t address, const void* buffer, size_t size) const;

        static std::optional<DWORD> find_process_id(std::wstring_view process_name);
        static HANDLE open_process_handle(DWORD process_id);

    private:
        DWORD process_id_{};
        HANDLE process_handle_{};
    };
}
