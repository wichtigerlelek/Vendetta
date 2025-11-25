#include "syswhispers.h"
#include <TlHelp32.h>
#include <print>

#include "../../VendettaCore/src/logger.h"

constexpr std::string VENDETTA_VERSION = "1.3.0 alpha";
constexpr auto VENDETTA_PATH = R"()";

namespace
{
	DWORD FindProcessId(const std::wstring& processName)
	{
		DWORD pId = 0;

		const HANDLE hSnap = CreateToolhelp32Snapshot(
			TH32CS_SNAPPROCESS, NULL);
		if (hSnap == INVALID_HANDLE_VALUE)
			return 0;

		PROCESSENTRY32W pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32W);
		if (Process32FirstW(hSnap, &pe32))
		{
			do
			{
				if (processName == pe32.szExeFile)
				{
					pId = pe32.th32ProcessID;
					break;
				}
			} while (Process32NextW(hSnap, &pe32));
		}
		CloseHandle(hSnap);
		return pId;
	}

	void InjectCoreDll(const DWORD pId)
        {
	        HANDLE hProcess = nullptr;
            OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
            CLIENT_ID clientId = { UlongToHandle(pId), nullptr };
            NTSTATUS status = Sw3NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr,
                                               &clientId);
            if (!NT_SUCCESS(status))
            {
                Log(LogError, "Sw3NtOpenProcess failed. Status = {:x}", static_cast<unsigned int>(status));
                return;
            }

            PVOID pDllPath = nullptr;
            SIZE_T pathLen = strlen(VENDETTA_PATH) + 1;
            SIZE_T regionSize = pathLen;
            status = Sw3NtAllocateVirtualMemory(hProcess, &pDllPath, 0, &regionSize, MEM_COMMIT, PAGE_READWRITE);
            if (!NT_SUCCESS(status))
            {
                Log(LogError, "Sw3NtAllocateVirtualMemory failed. Status = {:x}", static_cast<unsigned int>(status));
                Sw3NtClose(hProcess);
                return;
            }

            status = Sw3NtWriteVirtualMemory(hProcess, pDllPath, PVOID(VENDETTA_PATH), pathLen, nullptr);
            if (!NT_SUCCESS(status))
            {
                Log(LogError, "Sw3NtWriteVirtualMemory failed. Status = {:x}", static_cast<unsigned int>(status));

                SIZE_T freeSize = 0;
                Sw3NtFreeVirtualMemory(hProcess, &pDllPath, &freeSize, MEM_RELEASE);
                Sw3NtClose(hProcess);
                return;
            }

            auto loadLibraryAddr = reinterpret_cast<PVOID>(GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA"));
            if (!loadLibraryAddr) {
                Log(LogError, "Failed to resolve LoadLibraryA locally.");
                return;
            }

            HANDLE hLoadThread = nullptr;
            status = Sw3NtCreateThreadEx(&hLoadThread, THREAD_ALL_ACCESS, nullptr, hProcess,
                loadLibraryAddr, pDllPath,
                FALSE, 0, 0, 0, nullptr);

            if (!NT_SUCCESS(status))
            {
                Log(LogError, "Sw3NtCreateThreadEx failed. Status = {:x}", static_cast<unsigned int>(status));

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

	[[maybe_unused]] void TestCoreDllLocal(const DWORD pId)
	{
		const HANDLE hTarget = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pId);

		const HANDLE hDll = LoadLibraryA(VENDETTA_PATH);
		if (!hDll)
		{
			std::println("Error loading dll");
		}
		std::println("Press Enter to exit...");
		int input = getchar();

		CloseHandle(hDll);
		CloseHandle(hTarget);
	}
}


int main()
{
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

	const DWORD pId = FindProcessId(L"dummy2.exe");
	if (pId == 0)
	{
		Log(LogError, "Target not found");
		return 1;
	}

	InjectCoreDll(pId);

	return 0;
}