#pragma once
#include <syswhispers/syswhispers.h>
#include <ntpsapi.h>

#include <vector>
#include <TlHelp32.h>
#include <sstream>

constexpr unsigned long long operator"" _kb(const unsigned long long x)
{
	return x * 1024;
}

constexpr unsigned long long operator"" _mb(const unsigned long long x)
{
	return x * 1024 * 1024;
}


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

	struct SystemInformationBuffer
	{
		void* Buffer;

		explicit SystemInformationBuffer(void* p) : Buffer(p) {}

		~SystemInformationBuffer()
		{
			if (Buffer)
			{
				VirtualFree(Buffer, 0, MEM_RELEASE);
				Buffer = nullptr;
			}
		}

		SystemInformationBuffer(SystemInformationBuffer &&other) noexcept : Buffer(other.Buffer)
		{
			other.Buffer = nullptr;
		}

		SystemInformationBuffer(const SystemInformationBuffer&) = delete;
		SystemInformationBuffer& operator=(const SystemInformationBuffer&) = delete;

		explicit operator bool() const
		{
			return Buffer != nullptr;
		}
	};

	DWORD FindProcessId(const std::wstring &processName);
	SystemInformationBuffer GetSystemInfoClass(SYSTEM_INFORMATION_CLASS infoClass, ULONG startBufferSize = 512_kb);
	PVOID GetProcessObjectTypeFromTarget(DWORD targetPid);
	BYTE GetProcessObjectTypeIndex();
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
