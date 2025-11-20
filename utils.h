#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cctype>

namespace Utils {

    // --------------------------------------------------------------------------
    // String Conversion Helpers (ANSI <-> Unicode)
    // --------------------------------------------------------------------------
    inline std::wstring ToWide(const std::string& str) {
        if (str.empty()) return L"";
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
        std::wstring wstrTo(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
        return wstrTo;
    }

    inline std::string ToAnsi(const std::wstring& wstr) {
        if (wstr.empty()) return "";
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
        return strTo;
    }

    // --------------------------------------------------------------------------
    // System Privileges (Required for inspecting system services)
    // --------------------------------------------------------------------------
    inline bool EnableDebugPrivilege() {
        HANDLE hToken;
        TOKEN_PRIVILEGES tkp;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            return false;

        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);

        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        bool result = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
        CloseHandle(hToken);
        return result && (GetLastError() != ERROR_NOT_ALL_ASSIGNED);
    }

    // --------------------------------------------------------------------------
    // Data Visualization (Hex Dump like HxD/IDA)
    // --------------------------------------------------------------------------
    inline std::string HexDump(const void* data, size_t size) {
        const unsigned char* p = static_cast<const unsigned char*>(data);
        std::ostringstream oss;

        for (size_t i = 0; i < size; i += 16) {
            // Address offset
            oss << std::hex << std::setw(4) << std::setfill('0') << i << ": ";

            // Hex bytes
            for (size_t j = 0; j < 16; ++j) {
                if (i + j < size)
                    oss << std::hex << std::setw(2) << std::setfill('0') << (int)p[i + j] << " ";
                else
                    oss << "   ";
            }

            oss << " | ";

            // ASCII representation
            for (size_t j = 0; j < 16; ++j) {
                if (i + j < size) {
                    unsigned char c = p[i + j];
                    oss << (std::isprint(c) ? (char)c : '.');
                }
            }
            oss << "\n";
        }
        return oss.str();
    }
}
