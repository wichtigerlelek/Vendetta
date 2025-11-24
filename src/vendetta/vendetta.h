#pragma once
#include <fstream>
#include <print>
#include <vector>
#include <syswhispers.h>
#include <TlHelp32.h>
#include <sstream>


namespace vendetta
{
	struct Pattern
	{
		std::string signature;
		std::string name;
		std::vector<int> bytes;

		explicit Pattern(const std::string& sig, std::string name = "") : signature(sig),
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

	bool inject_phantom_dll(const PROCESS_INFORMATION& pi,
		const std::wstring& legitimate_dll_path);
	HANDLE hijack_process_handle(DWORD target_pid);
	HANDLE find_process_to_proxy(DWORD target_pid);

	class loader
	{
		STARTUPINFOA si_{};
		PROCESS_INFORMATION pi_{};
		const std::wstring& dll_path_;

	public:
		explicit loader(std::wstring& dll_path)
			: dll_path_(dll_path)
		{
		}

		~loader();

		[[nodiscard]] PROCESS_INFORMATION get_process_info() const { return pi_; }
		bool create_process(const LPCSTR& process_path, bool create_suspended = false);
		bool attach_to_process(DWORD pid);
		bool attach_to_process_by_name(const std::wstring& process_name);
		bool find_process_to_proxy() const;
		[[nodiscard]] bool inject(const std::wstring& dll_path) const;
	};
}