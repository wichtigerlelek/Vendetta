#pragma once
namespace vendetta
{
	bool inject_phantom_dll(const PROCESS_INFORMATION& pi, const BYTE* buf, SIZE_T buf_size, const std::wstring& legitimate_dll_path);

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

		bool create_dummy_process(bool create_suspended = false);
		bool attach_to_process(const DWORD pid);
		bool attach_to_process_by_name(const std::wstring& process_name);
		bool inject(const std::wstring& benign_dll) const;
	};
}