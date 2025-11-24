#include "vendetta/vendetta.h"

#include "payload.h"


int main(int argc, char** argv)
{
	if (argc != 4)
	{
		std::println("Usage: vendetta.exe -pid <pid> <dll path>");
		std::println("       vendetta.exe -proc <process name> <dll path>");
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
	const auto dll_path = std::wstring(dll_path_str.begin(),
	                                     dll_path_str.end());

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

		if (!inj.attach_to_process(pid))
		{
			std::println("[-] Failed to attach to process by PID.");
			return 1;
		}
	}
	else if (option == "-proc")
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
