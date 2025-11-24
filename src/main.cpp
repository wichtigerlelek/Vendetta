#include "vendetta/vendetta.h"

#include "payload.h"


int main(int argc, char** argv)
{
	if (argc == 1)
	{
		std::println("Creating dummy for testing purposes...");
		vendetta::injector inj(shellc_hello);
		if (!inj.create_process(R"(.\dummy\dummy.exe)", false))
		{
			std::println("[-] Failed to launch dummy.exe.");
			return 1;
		}
		Sleep(1000);
		if (!inj.inject(LR"(.\dummy\GameOverlayRenderer64.dll)"))
		{
			std::println("[-] Injection failed.");
			return 1;
		}

		std::println("[+] Injection completed successfully.");
		return 0;
	}

	if (argc < 4)
	{
		std::println("Usage: vendetta.exe (-pid <pid> | -proc <process name>) <dll path> [-m (open_handle|hijack_handle)]");
		std::println("");
		std::println("Examples:");
		std::println(R"(  vendetta.exe -pid 1234 C:\path\to\dll.dll)");
		std::println(R"(  vendetta.exe -proc notepad.exe C:\path\to\dll.dll)");
		std::println(
			R"(  vendetta.exe -pid 1234 C:\path\to\dll.dll -m open_handle)");
		std::println(
			R"(  vendetta.exe -m hijack_handle -proc notepad.exe C:\path\to\dll.dll)");
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

	std::string option;
	std::string target;
	std::wstring dll_path;
	vendetta::injector::retrieve_handle_method handle_method = vendetta::injector::hijack_handle;

	bool has_option = false;
	bool has_target = false;
	bool has_dll = false;

	for (int i = 1; i < argc; i++)
	{
		std::string arg(argv[i]);

		if (arg == "-pid" || arg == "-proc")
		{
			if (i + 1 >= argc)
			{
				std::println("[-] {} requires an argument.", arg);
				return 1;
			}
			option = arg;
			target = argv[++i];
			has_option = true;
			has_target = true;
		}
		else if (arg == "-m")
		{
			if (i + 1 >= argc)
			{
				std::println("[-] -m requires an argument (open_handle or hijack_handle).");
				return 1;
			}
			std::string method(argv[++i]);
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
				std::println("[-] Invalid handle method '{}'. Use 'open_handle' or 'hijack_handle'.", method);
				return 1;
			}
		}
		else if (!has_dll && arg[0] != '-')
		{
			if (has_option && has_target)
			{
				dll_path = std::wstring(arg.begin(), arg.end());
				has_dll = true;
			}
		}
	}

	if (!has_option || !has_target || !has_dll)
	{
		std::println("[-] Missing required arguments.");
		std::println("Usage: vendetta.exe (-pid <pid> | -proc <process name>) <dll path> [-m (open_handle|hijack_handle)]");
		return 1;
	}

	vendetta::injector inj(shellc_hello);

	if (option == "-pid")
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

		if (!inj.attach_to_process(pid, handle_method))
		{
			std::println("[-] Failed to attach to process by PID.");
			return 1;
		}
	}
	else if (option == "-proc")
	{
		std::wstring process_name(target.begin(), target.end());

		if (!inj.attach_to_process_by_name(process_name, handle_method))
		{
			std::println("[-] Failed to attach to process by name.");
			return 1;
		}
	}
	else
	{
		std::println("[-] Invalid option. Use -pid for PID or -proc for process name.");
		return 1;
	}

	if (!inj.inject(dll_path))
	{
		std::println("[-] Injection failed.");
		return 1;
	}

	std::println("[+] Injection completed successfully.");
	return 0;
}
