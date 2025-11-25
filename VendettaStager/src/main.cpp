#include "phnt_windows.h"

#include <print>


int main()
{
	HANDLE hDll = LoadLibraryA("./VendettaCore.dll");
	if (!hDll)
	{
		std::println("Error loading dll");
	}

	return 0;
}