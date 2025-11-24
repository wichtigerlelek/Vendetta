#pragma once
#include <print>
#include <vector>
#include <syswhispers.h>
#include <TlHelp32.h>
#include <sstream>


namespace vendetta
{
	bool inject_phantom_dll(const PROCESS_INFORMATION& pi, const BYTE* buf, SIZE_T buf_size, const std::wstring& legitimate_dll_path);
	HANDLE hijack_process_handle(const DWORD target_pid);

	class injector
	{
		STARTUPINFOA si_{};
		PROCESS_INFORMATION pi_{};
		BYTE* buf_;
		SIZE_T buf_size_;

	public:
		template <SIZE_T N>
		explicit injector(BYTE(&data)[N])
			: buf_(data), buf_size_(N)
		{
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