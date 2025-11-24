#pragma once

#include <sstream>

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

namespace voidStare
{
	inline MODULEENTRY32W GetModuleEntry32W(const wchar_t* moduleName,
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
			}
			while (Module32NextW(hSnap, &me32));
		}
		CloseHandle(hSnap);
		return {};
	}

	inline PVOID FindSignature(const PROCESS_INFORMATION& pi,
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
}
