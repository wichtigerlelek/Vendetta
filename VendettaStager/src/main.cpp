#include <iostream>
#include <map>
#include <syswhispers/syswhispers.h>
#include <TlHelp32.h>
#include <print>
#include <filesystem>
#include <ntexapi.h>
#include <phnt_ntdef.h>

#include "vendetta/vendetta.h"
#include "vendetta/logger.h"
#include "config.h"

namespace
{
	void EnableWindowsAnsi() {
		const HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
		const HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
		if (hOut == INVALID_HANDLE_VALUE || hErr == INVALID_HANDLE_VALUE) return;

		DWORD dwMode = 0;

		if (GetConsoleMode(hOut, &dwMode)) {
			dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
			SetConsoleMode(hOut, dwMode);
		}

		if (GetConsoleMode(hErr, &dwMode)) {
			dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
			SetConsoleMode(hErr, dwMode);
		}
	}

	bool SetPrivilege(const char* szPrivilege, const bool bState = true)
	{
		HANDLE hToken;
		if (!OpenProcessToken(GetCurrentProcess(),
		                      TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		                      &hToken))
			return false;

		TOKEN_PRIVILEGES TokenPrivileges = {0};
		TokenPrivileges.PrivilegeCount = 1;
		TokenPrivileges.Privileges[0].Attributes = bState
			                                           ? SE_PRIVILEGE_ENABLED
			                                           : 0;

		if (!LookupPrivilegeValueA(nullptr, szPrivilege,
		                           &TokenPrivileges.Privileges[0].Luid))
		{
			CloseHandle(hToken);
			return false;
		}

		if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges,
		                           sizeof(TOKEN_PRIVILEGES), nullptr,
		                           nullptr))
		{
			CloseHandle(hToken);
			return false;
		}


		CloseHandle(hToken);
		return (GetLastError() == ERROR_SUCCESS);
	}

	std::map<DWORD, std::wstring> GetProcessMap()
	{
		std::map<DWORD, std::wstring> processMap;
		const auto sysInfoBuffer = Vendetta::GetSystemInfoClass(
			SystemProcessInformation, 6_mb);
		if (!sysInfoBuffer.Buffer) return processMap;

		auto pProcessInfo = static_cast<PSYSTEM_PROCESS_INFORMATION>(
			sysInfoBuffer.Buffer);
		while (true)
		{
			const DWORD pid = static_cast<DWORD>(reinterpret_cast<uintptr_t>(
				pProcessInfo->UniqueProcessId));
			const std::wstring processName = pProcessInfo->ImageName.Buffer
				                                 ? std::wstring(
					                                 pProcessInfo->ImageName.
					                                 Buffer,
					                                 pProcessInfo->ImageName.
					                                 Length / sizeof(wchar_t))
				                                 : L"System Idle Process";
			processMap[pid] = processName;
			if (pProcessInfo->NextEntryOffset == 0)
				break;
			pProcessInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
				reinterpret_cast<uint8_t*>(pProcessInfo) + pProcessInfo->
				NextEntryOffset);
		}

		return processMap;
	}

	void FindHandleToProcess(const DWORD targetPid)
	{
		auto processMap = GetProcessMap();
		std::wstring targetName = processMap.contains(targetPid)
			                          ? processMap[targetPid]
			                          : L"Unknown";

		auto handleBuffer = Vendetta::GetSystemInfoClass(
			SystemExtendedHandleInformation, 6_mb);
		const auto pHandleInfo = static_cast<PSYSTEM_HANDLE_INFORMATION_EX>
			(handleBuffer.Buffer);
		PVOID targetObjectAddress = Vendetta::GetProcessObjectTypeFromTarget(
			targetPid);
		const DWORD myPid = GetCurrentProcessId();


		constexpr ACCESS_MASK requiredAccess = PROCESS_VM_WRITE |
			PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
		for (ULONG_PTR i = 0; i < pHandleInfo->NumberOfHandles; i++)
		{
			const auto& entry = pHandleInfo->Handles[i];

			if (entry.UniqueProcessId == ULongToHandle(4))
				continue; // System process

			if (entry.Object != targetObjectAddress)
				continue;

			if ((entry.GrantedAccess & requiredAccess) != requiredAccess)
				continue;

			std::wstring ownerName = L"Unknown";
			if (DWORD ownerPid = reinterpret_cast<DWORD>(entry.UniqueProcessId); processMap.contains(ownerPid))
				ownerName = processMap[ownerPid];

			if (ownerName == L"csrss.exe" || ownerName == L"lsass.exe")
				continue;


			Log(LogInfo, "{} ({:d}) holds a handle to {} with Access: 0x{:x}",
			    std::string(ownerName.begin(), ownerName.end()),
			    reinterpret_cast<DWORD>(entry.UniqueProcessId),
			    std::string(targetName.begin(), targetName.end()),
			    entry.GrantedAccess);
		}
	}

	void InjectCoreDll(const DWORD pId, const std::string& coreDllPath)
	{
		HANDLE hProcess = nullptr;
		OBJECT_ATTRIBUTES objAttr = {sizeof(OBJECT_ATTRIBUTES)};
		CLIENT_ID clientId = {UlongToHandle(pId), nullptr};
		NTSTATUS status = Sw3NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS,
		                                   &objAttr,
		                                   &clientId);
		if (!NT_SUCCESS(status))
		{
			Log(LogError, "Sw3NtOpenProcess failed. Status = {:x}",
			    static_cast<unsigned int>(status));
			return;
		}

		PVOID pDllPath = nullptr;
		SIZE_T pathLen = strlen(coreDllPath.c_str()) + 1;
		SIZE_T regionSize = pathLen;
		status = Sw3NtAllocateVirtualMemory(hProcess, &pDllPath, 0, &regionSize,
		                                    MEM_COMMIT, PAGE_READWRITE);
		if (!NT_SUCCESS(status))
		{
			Log(LogError, "Sw3NtAllocateVirtualMemory failed. Status = {:x}",
			    static_cast<unsigned int>(status));
			Sw3NtClose(hProcess);
			return;
		}

		status = Sw3NtWriteVirtualMemory(hProcess, pDllPath,
		                                 PVOID(coreDllPath.c_str()), pathLen,
		                                 nullptr);
		if (!NT_SUCCESS(status))
		{
			Log(LogError, "Sw3NtWriteVirtualMemory failed. Status = {:x}",
			    static_cast<unsigned int>(status));

			SIZE_T freeSize = 0;
			Sw3NtFreeVirtualMemory(hProcess, &pDllPath, &freeSize, MEM_RELEASE);
			Sw3NtClose(hProcess);
			return;
		}

		auto loadLibraryAddr = reinterpret_cast<PVOID>(GetProcAddress(
			GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"));
		if (!loadLibraryAddr)
		{
			Log(LogError, "Failed to resolve LoadLibraryA locally.");
			return;
		}

		HANDLE hLoadThread = nullptr;
		status = Sw3NtCreateThreadEx(&hLoadThread, THREAD_ALL_ACCESS, nullptr,
		                             hProcess,
		                             loadLibraryAddr, pDllPath,
		                             FALSE, 0, 0, 0, nullptr);

		if (!NT_SUCCESS(status))
		{
			Log(LogError, "Sw3NtCreateThreadEx failed. Status = {:x}",
			    static_cast<unsigned int>(status));

			SIZE_T freeSize = 0;
			Sw3NtFreeVirtualMemory(hProcess, &pDllPath, &freeSize, MEM_RELEASE);
			Sw3NtClose(hProcess);
			return;
		}

		status = Sw3NtWaitForSingleObject(hLoadThread, FALSE, nullptr);

		SIZE_T freeSize = 0;
		Sw3NtFreeVirtualMemory(hProcess, &pDllPath, &freeSize, MEM_RELEASE);

		Sw3NtClose(hLoadThread);
		Sw3NtClose(hProcess);

		Log(LogInfo, "VendettaCore injected successfully.");
	}

	void FreeCoreDll(const DWORD pId)
	{
		PROCESS_INFORMATION pi = {0};
		pi.dwProcessId = pId;
		Log(LogInfo, "Searching for module to unload: {}", VENDETTA_NAME);

		const MODULEENTRY32W me32 = Vendetta::GetModuleEntry32W(
			std::wstring(VENDETTA_NAME.begin(), VENDETTA_NAME.end()).data(),
			pi);
		if (me32.modBaseAddr == nullptr)
		{
			Log(LogError, "Module not found in target process.");
			return;
		}
		Log(LogInfo, "Found module at: {:p}",
		    static_cast<PVOID>(me32.modBaseAddr));

		HANDLE hProcess = nullptr;
		OBJECT_ATTRIBUTES objAttr = {sizeof(OBJECT_ATTRIBUTES)};
		CLIENT_ID clientId = {UlongToHandle(pId), nullptr};
		NTSTATUS status = Sw3NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS,
		                                   &objAttr,
		                                   &clientId);
		if (!NT_SUCCESS(status))
		{
			Log(LogError, "Sw3NtOpenProcess failed. Status = {:x}",
			    static_cast<unsigned int>(status));
			return;
		}

		HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
		if (!hKernel32)
		{
			Log(LogError, "Failed to get local Kernel32 handle.");
			CloseHandle(hProcess);
			return;
		}

		auto pFreeLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(
			GetProcAddress(
				hKernel32, "FreeLibrary"));
		if (!pFreeLibrary)
		{
			Log(LogError, "Failed to resolve FreeLibrary address.");
			CloseHandle(hProcess);
			return;
		}

		Log(LogInfo, "Creating remote thread to unload module...");
		HANDLE hThread = CreateRemoteThread(
			hProcess,
			nullptr,
			0,
			pFreeLibrary,
			(LPVOID)me32.modBaseAddr,
			0,
			nullptr
		);
		if (!hThread)
		{
			Log(LogError, "CreateRemoteThread failed. Error = {}",
			    GetLastError());
			CloseHandle(hProcess);
			return;
		}

		WaitForSingleObject(hThread, INFINITE);

		DWORD exitCode = 0;
		if (GetExitCodeThread(hThread, &exitCode))
		{
			if (exitCode != 0)
				Log(LogInfo, "Module unloaded successfully.");
			else
				Log(LogWarn,
				    "FreeLibrary returned FALSE. The module might be pinned or invalid.");
		}

		CloseHandle(hThread);
		CloseHandle(hProcess);
	}
}


int main()
{
	EnableWindowsAnsi();

	std::println(
		R"(____   ____                 .___      __    __          
\   \ /   /____   ____    __| _/_____/  |__/  |______   
 \   Y   // __ \ /    \  / __ |/ __ \   __\   __\__  \  
  \     /\  ___/|   |  \/ /_/ \  ___/|  |  |  |  / __ \_
   \___/  \___  >___|  /\____ |\___  >__|  |__| (____  /
                                                     \/ 
        .-------------------------------------.          
        |  Phantom DLL injector v{}  |          
        |       Author: (wichtigerlelek)      |          
        '-------------------------------------'          )", VENDETTA_VERSION);
	if (!SetPrivilege("SeDebugPrivilege"))
	{
		Log(LogError,
		    "Failed to set SeDebugPrivilege. This program needs to be ran as Administrator");
		return 1;
	}

	if constexpr (COPY_AND_DELETE)
		Log(LogWarn, "COPY_AND_DELETE is enabled. This is not bad, it is just a bit less stealthy");

	if constexpr (FIND_HANDLE_TO_TARGET)
		Log(LogWarn, "FIND_HANDLE_TO_PROCESS is enabled. This is just a quality of life feature");

	auto getExeDirectory = [&]
	{
		char buffer[MAX_PATH];
		if (GetModuleFileNameA(nullptr, buffer, MAX_PATH) == 0)
		{
			return std::string("");
		}
		const std::filesystem::path exePath(buffer);
		return exePath.parent_path().string();
	};

	std::string coreDllPath = (std::filesystem::path(getExeDirectory()) /
		VENDETTA_NAME).string();

	if (!std::filesystem::exists(coreDllPath))
	{
		Log(LogError, "VendettaCore.dll not found at: {}", coreDllPath);
		return 1;
	}

	Log(LogInfo, "Target: {}", std::string(TARGET.begin(), TARGET.end()));
	Log(LogInfo, "Vendetta Core: {}", coreDllPath);

	const DWORD pId = Vendetta::FindProcessId(TARGET);
	if (pId == 0)
	{
		Log(LogError, "Target not found");
		return 2;
	}

	if constexpr (FIND_HANDLE_TO_TARGET)
	{
		Log(LogInfo, "Searching for handles to {}", std::string(TARGET.begin(), TARGET.end()));
		FindHandleToProcess(pId);
	}

	DWORD target = 0;
	std::print(">> Inject Core into Proxy (PID): ");
	std::cin >> target;
	if (target != 0)
	{
		Log(LogInfo, "Injecting into PID = {}", target);
		switch (CORE_INJECTION_METHOD)
		{
		case CoreInjectionMethod::LoadLibraryInjection:
			InjectCoreDll(target, coreDllPath);
			for (int i = 0; i < 3; ++i)
			{
				Log(LogWarn, "Unloading in {}", 3 - i);
				Sleep(1000);
			}
			FreeCoreDll(target);
			break;
		case CoreInjectionMethod::PhantomDllWithManualMapping:
			Log(LogError, "PhantomDllWithManualMapping is not implemented yet.");
			break;
		}
	}
	return 0;
}
