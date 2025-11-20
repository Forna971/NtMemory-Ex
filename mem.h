#pragma once
#include <memory>
#include <string_view>
#include <optional>
#include <Windows.h>

namespace Memory {
    namespace detail { class MemoryImpl; }

    class Process {
    public:
        static std::optional<Process> attach(std::wstring_view process_name, bool wait_for_process = false);

        Process(Process&& other) noexcept;
        Process& operator=(Process&& other) noexcept;
        ~Process();

        Process(const Process&) = delete;
        Process& operator=(const Process&) = delete;

        uintptr_t get_module_base(std::wstring_view module_name) const;

        template <typename T>
        T read(uintptr_t address) const;

        template <typename T>
        bool write(uintptr_t address, const T& value) const;

        bool read_buffer(uintptr_t address, void* buffer, size_t size) const;
        bool write_buffer(uintptr_t address, const void* buffer, size_t size) const;

    private:
        explicit Process(std::unique_ptr<detail::MemoryImpl>&& pimpl);
        std::unique_ptr<detail::MemoryImpl> pimpl_;
    };

    template <typename T>
    T Process::read(uintptr_t address) const {
        T buffer{};
        read_buffer(address, &buffer, sizeof(T));
        return buffer;
    }

    template <typename T>
    bool Process::write(uintptr_t address, const T& value) const {
        return write_buffer(address, &value, sizeof(T));
    }
}
