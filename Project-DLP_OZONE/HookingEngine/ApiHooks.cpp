#include "pch.h"
#include "Minhook.h"
#include "ApiHooks.h"
#include "Logger.h"
#include "PolicyManager.h"
#include <iostream>
#include <Windows.h>

HHOOK g_hKeyBoardHook = NULL;
typedef HANDLE(WINAPI* SetClipboardData_t)(UINT uFormat, HANDLE hMem);
typedef HANDLE(WINAPI* GetClipboardData_t)(UINT uFormat);
typedef HANDLE(WINAPI* EmptyClipboard_t)();
typedef HANDLE(WINAPI* CreateFileW_t)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
SetClipboardData_t pSetClipboardData = nullptr;
GetClipboardData_t pGetClipboardData = nullptr;
EmptyClipboard_t pEmptyClipboard = nullptr;
CreateFileW_t pCreateFileW = nullptr;

HANDLE WINAPI mySetClipboardData(UINT uFormat, HANDLE hMem)
{
	if (!Policymanager::IsCopyAllowed())
	{
		Logger::Log("Clipboard Copy Blocked by Ozone!");
		MessageBoxA(NULL, "Copy Blocked by Ozone!", "Ozone Alert!...", MB_ICONWARNING);
		return NULL; //block copy
	}
	
	Logger::Log("Clipboard Copy Allowed by Ozone!");
	return pSetClipboardData(uFormat, hMem); //alow normally
}

HANDLE WINAPI myGetClipboardData(UINT uFormat)
{
	if (!Policymanager::IsPasteAllowed())
	{
		Logger::Log("Clipboard Paste Blocked by Ozone!");
		MessageBoxA(NULL, "Pasting Blocked by Ozone!", "Ozone Alert!...", MB_ICONWARNING);
		return NULL; //block paste
	}

	Logger::Log("Clipboard Pasting Allowed by Ozone!");
	return pGetClipboardData(uFormat); //alow normally
}

HANDLE WINAPI myEmptyClipboard()
{
	bool ctrlDown = (GetAsyncKeyState(VK_CONTROL) & 0x8000); // ctrl
	bool xDown = (GetAsyncKeyState(0x58) & 0x8000); //0x58 = x

	if (ctrlDown && xDown)
	{
		if (!Policymanager::IsCutAllowed())
		{
			Logger::Log("Clipboard Cut Blocked by Ozone!");
			MessageBoxA(NULL, "Cutting Blocked by Ozone!", "Ozone Alert!...", MB_ICONWARNING);
			return NULL; //block cut
		}
	}
	
	Logger::Log("Clipboard Cutting Allowed by Ozone!");
	return pEmptyClipboard(); //alow normally
}

HANDLE WINAPI myCreateFileW(
	LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	if (!Policymanager::IsFileSaveAllowed())
	{
		Logger::Log("File Saving Blocked by Ozone!");
		MessageBoxA(NULL, "File Saving Blocked by Ozone!", "Ozone Alert!...", MB_ICONWARNING);
		SetLastError(ERROR_ACCESS_DENIED);
		return INVALID_HANDLE_VALUE;
	}
	Logger::Log("File Saving Allowed by Ozone!");
	return pCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
		lpSecurityAttributes, dwCreationDisposition,
		dwFlagsAndAttributes, hTemplateFile); //alow normally
}

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	if (nCode == HC_ACTION && wParam == WM_KEYDOWN)
	{
		KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)lParam;

		if (p->vkCode == VK_SNAPSHOT)
		{
			if (!Policymanager::IsPrintScreenAllowed())
			{
				Logger::Log("Clipboard Screenshot Blocked by Ozone!");
				MessageBoxA(NULL, "Screenshot Blocked by Ozone!", "Ozone Alert!...", MB_ICONWARNING);
				return 1; //block Printscreen
			}
		}
	}

	Logger::Log("Clipboard Screenshot Allowed by Ozone!");
	return CallNextHookEx(g_hKeyBoardHook, nCode, wParam, lParam);
}

// Thread to run the message loop, allowing the hook to work
DWORD WINAPI KeyboardHookThread(LPVOID) {
	g_hKeyBoardHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, GetModuleHandle(NULL), 0);

	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	return 0;
}

void InstallClipboardHook()
{
	HMODULE hUser32 = GetModuleHandleA("user32.dll");
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (hUser32 && hKernel32)
	{
		void* target1 = GetProcAddress(hUser32, "SetClipboardData");
		void* target2 = GetProcAddress(hUser32, "GetClipboardData");
		void* target3 = GetProcAddress(hUser32, "EmptyClipboard");
		void* target4 = GetProcAddress(hKernel32, "CreateFileW");
		if (target1 && target2 && target3 && target4)
		{
			MH_CreateHook(target1, &mySetClipboardData, reinterpret_cast<void**>(&pSetClipboardData));
			MH_EnableHook(target1);
			MH_CreateHook(target2, &myGetClipboardData, reinterpret_cast<void**>(&pGetClipboardData));
			MH_EnableHook(target2);
			MH_CreateHook(target3, &myEmptyClipboard, reinterpret_cast<void**>(&pEmptyClipboard));
			MH_EnableHook(target3);
			MH_CreateHook(target4, &myCreateFileW, reinterpret_cast<void**>(&pCreateFileW));
			MH_EnableHook(target4);
			// Start the hook in a new thread to keep the message loop running
			CreateThread(NULL, 0, KeyboardHookThread, NULL, 0, NULL);
		}
		else
		{
			std::cout << "Error occured on InstallClipboard Hook error no :" << GetLastError() << std::endl;
			MessageBoxA(NULL, "something failed!", "Ozone Alert!...", MB_ICONWARNING);
		}
	}
	else
	{
		MessageBoxA(NULL, "Kernel32 open  failed!", "Ozone Alert!...", MB_ICONWARNING);
	}
}



void RemoveClipboardHook()
{
	HMODULE hUser32 = GetModuleHandleA("user32.dll");
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (hUser32 && hKernel32)
	{
		void* target1 = GetProcAddress(hUser32, "SetClipboardData");
		void* target2 = GetProcAddress(hUser32, "GetClipboardData");
		void* target3 = GetProcAddress(hUser32, "EmptyClipboard");
		void* target4 = GetProcAddress(hKernel32, "CreateFileW");
		if (target1 && target2 && target3 && target4)
		{
			MH_DisableHook(target1);
			MH_RemoveHook(target1);
			MH_DisableHook(target2);
			MH_RemoveHook(target2);
			MH_DisableHook(target3); 
			MH_RemoveHook(target3);
			MH_DisableHook(target4);
			MH_RemoveHook(target4);
			// Unhook PrintScreen blocker
			if (g_hKeyBoardHook) {
				UnhookWindowsHookEx(g_hKeyBoardHook);
				g_hKeyBoardHook = NULL;
			}

		}
		else
		{
			std::cout << "Error occured on RemoveClipboard Hook error no :" << GetLastError() << std::endl;
		}
	}
}