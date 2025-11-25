#pragma once
#include <vector>
#include "syswhispers.h"
#include <TlHelp32.h>
#include <sstream>

namespace Vendetta
{
	struct Pattern
	{
		std::string signature;
		std::string name;
		std::vector<int> bytes;

		explicit Pattern(const std::string& sig, std::string name = "") :
			signature(sig),
			name(std::move(name)), bytes(ParsePattern(sig))
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

	DWORD FindProcessId(const std::wstring &processName);
	HANDLE FindProcessHandleInternal(const DWORD &targetPid);

	MODULEENTRY32W GetModuleEntry32W(const wchar_t* moduleName,
	                                 const PROCESS_INFORMATION& pi);
	PVOID FindSignature(const PROCESS_INFORMATION& pi,
	                    const wchar_t* moduleName, Pattern pattern);
	bool ExecuteHijackThreadApcInstant(const PROCESS_INFORMATION& pi,
	                                   PPS_APC_ROUTINE
	                                   baseAddress,
	                                   PVOID arg1 = nullptr,
	                                   PVOID arg2 = nullptr,
	                                   PVOID arg3 = nullptr);
	bool LinkModuleToPeb(const PROCESS_INFORMATION& pi,
	                     PVOID moduleBaseAddress,
	                     PVOID moduleEntryPoint,
	                     ULONG imageSize,
	                     const std::wstring& imagePath);
	bool InjectPhantomDll(const PROCESS_INFORMATION& pi, const BYTE* buf,
	                      SIZE_T bufSize,
	                      const std::wstring& legitimateDllPath);
}
