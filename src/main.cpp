#include "vendetta/vendetta.h"
#include <iostream>

int main()
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

	std::wstring dll_path = LR"(C:\Users\felix\Documents\Projects\Vendetta\dummy\HelloDll.dll)";
	std::wstring target_name = L"dummy.exe";
	vendetta::loader l(dll_path);
	if (!l.attach_to_process_by_name(target_name))
	{
		std::println("[-] Failed to attach to {}.", std::string(target_name.begin(), target_name.end()));
		return 1;
	}
	if (!l.find_process_to_proxy())
	{
		std::println("[-] Failed to scan for proxy.");
		return 1;
	}
	return 0;
}
