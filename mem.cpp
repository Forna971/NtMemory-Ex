#include "mem.h"
#include "detail/mem_pimpl.h"
#include <utility>
#include <thread>
#include <chrono>

namespace Memory {

    std::optional<Process> Process::attach(std::wstring_view process_name, bool wait_for_process) {
        if (!detail::MemoryImpl::initialize_syscalls()) {
            return std::nullopt;
        }

        std::optional<DWORD> pid;
        do {
            pid = detail::MemoryImpl::find_process_id(process_name);
            if (!pid && wait_for_process) {
                using namespace std::chrono_literals;
                std::this_thread::sleep_for(100ms);
            }
        } while (!pid && wait_for_process);

        if (!pid) return std::nullopt;

        HANDLE handle = detail::MemoryImpl::open_process_handle(*pid);
        if (!handle || handle == INVALID_HANDLE_VALUE) return std::nullopt;

        auto pimpl = std::make_unique<detail::MemoryImpl>(*pid, handle);
        return std::optional<Process>(Process(std::move(pimpl)));
    }

    Process::Process(std::unique_ptr<detail::MemoryImpl>&& pimpl) : pimpl_(std::move(pimpl)) {}
    Process::~Process() = default;
    Process::Process(Process&& other) noexcept : pimpl_(std::move(other.pimpl_)) {}

    Process& Process::operator=(Process&& other) noexcept {
        if (this != &other) {
            pimpl_ = std::move(other.pimpl_);
        }
        return *this;
    }

    uintptr_t Process::get_module_base(std::wstring_view module_name) const {
        return pimpl_ ? pimpl_->find_module_base(module_name) : 0;
    }

    bool Process::read_buffer(uintptr_t address, void* buffer, size_t size) const {
        return pimpl_ ? pimpl_->read_memory(address, buffer, size) : false;
    }

    bool Process::write_buffer(uintptr_t address, const void* buffer, size_t size) const {
        return pimpl_ ? pimpl_->write_memory(address, buffer, size) : false;
    }
}
