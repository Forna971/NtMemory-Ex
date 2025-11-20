# NtMemory-Ex 🧠

> A high-performance, stealthy external memory wrapper for Windows, leveraging direct syscalls and the Pimpl idiom.

![Platform](https://img.shields.io/badge/Platform-Windows%20x64-0078D6?logo=windows)
![Standard](https://img.shields.io/badge/C%2B%2B-17%2F20-blue?logo=c%2B%2B)
![Technique](https://img.shields.io/badge/Technique-Direct%20Syscalls-red)

## ⚡ Overview

**NtMemory-Ex** is a C++ library designed for external process manipulation. Unlike standard memory wrappers that rely on `ReadProcessMemory` (RPM) and `WriteProcessMemory` (WPM) APIs via `kernel32.dll`, this library implements **Direct Syscalls**.

It manually parses the `ntdll.dll` Export Address Table (EAT) to resolve System Service Numbers (SSNs) and generates assembly stubs at runtime. This approach bypasses user-mode hooks placed by Anti-Cheats or EDRs on standard WinAPI functions.

## 🛠️ Technical Architecture

### 1. Direct Syscall Invocation
Instead of calling WinAPIs, `NtMemory-Ex` acts as its own loader:
*   **Dynamic SSN Resolution**: Parses the PE headers of `ntdll.dll` in memory to find `NtReadVirtualMemory` and `NtWriteVirtualMemory`.
*   **JIT Assembly Stubs**: Allocates executable memory (`PAGE_EXECUTE_READWRITE`) and writes raw assembly instructions (`mov r10, rcx`, `syscall`) to execute the transition to kernel mode directly.

### 2. Pimpl Idiom (Pointer to Implementation)
The public interface (`Process` class) is completely decoupled from the internal logic via `std::unique_ptr`.
*   **ABI Stability**: Changes to the internal memory logic do not affect the public header.
*   **Compilation Speed**: Reduces header dependencies in the consuming project.

### 3. RAII Resource Management
Handles and allocated memory are managed automatically using C++ smart pointers and destructors, ensuring no memory leaks or dangling handles.

## 🚀 Usage

```cpp
#include "mem.h"
#include <iostream>

int main() {
    // Attach to process (waits until found)
    auto proc = Memory::Process::attach(L"target_process.exe", true);

    if (proc) {
        std::cout << "Attached! PID found." << std::endl;

        // Get Module Base
        uintptr_t client = proc->get_module_base(L"client.dll");

        // Read Memory (Template-based)
        int health = proc->read<int>(client + 0x100);
        
        // Write Memory
        proc->write<int>(client + 0x100, 1337);
    }

    return 0;}
```

📂 Project Structure

    mem.h - Public Interface (RAII wrapper).

    detail/mem_pimpl.cpp - Core Logic: Syscall generation, PE Parsing, Assembly stubs.

    utils.h - Vector math and WorldToScreen helpers.

⚠️ Disclaimer

This software explores undocumented Windows Internals and memory manipulation techniques. It is intended for educational purposes, reverse engineering research, and defensive security testing.
<div align="center">
Developed by <a href="https://github.com/Forna971"><b>Forna971</b></a>
</div>
