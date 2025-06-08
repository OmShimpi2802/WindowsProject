#include "pch.h"
#include <windows.h>
#include <minhook.h>
#include <string>
#include <fstream>
#include <unordered_set>
#include "allowlist.h"


typedef BOOL(WINAPI* CreateProcessW_t)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
    LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

CreateProcessW_t originalCreateProcessW = nullptr;
std::unordered_set<std::wstring> allowlist;

bool IsAllowed(const std::wstring& exeName) {
    return allowlist.count(exeName) > 0;
}

void LoadAllowlist() {
    std::wifstream file("allowlist.txt");
    std::wstring line;
    while (std::getline(file, line)) {
        allowlist.insert(line);
    }
}

BOOL WINAPI HookedCreateProcessW(
    LPCWSTR appName, LPWSTR cmdLine,
    LPSECURITY_ATTRIBUTES p1, LPSECURITY_ATTRIBUTES p2,
    BOOL inherit, DWORD flags, LPVOID env,
    LPCWSTR curDir, LPSTARTUPINFOW startInfo,
    LPPROCESS_INFORMATION procInfo) {

    std::wstring process = appName ? appName : cmdLine;
    if (!IsAllowed(process)) {
        //OutputDebugStringW((L"Blocked process: " + process + L"\n").c_str());
        MessageBoxA(NULL, "File opening Blocked by Om shimpi!", "Ozone Alert!...", MB_ICONWARNING);
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return originalCreateProcessW(appName, cmdLine, p1, p2, inherit, flags, env, curDir, startInfo, procInfo);
}

void InitHook() {
    LoadAllowlist();
    MH_Initialize();
    MH_CreateHook(&CreateProcessW, &HookedCreateProcessW, reinterpret_cast<LPVOID*>(&originalCreateProcessW));
    MH_EnableHook(&CreateProcessW);
}

void Unhook() {
    MH_DisableHook(&CreateProcessW);
    MH_Uninitialize();
}
