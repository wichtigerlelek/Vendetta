#pragma once
constexpr std::string VENDETTA_VERSION = "1.3.6 alpha";

enum class CoreInjectionMethod
{
	LoadLibraryInjection,		 // Default LoadLibraryA injection
	PhantomDllWithManualMapping, // Not implemented yet
};

enum class ProxyTarget
{
	SelectByPid, // User inputs PID
	Discord,	 // Target Discord.exe
	Svchost,	 // Target svchost.exe
};

enum class HandleMode
{
	ForceOpen,		   // Always call OpenProcess (Loud)
	HijackInternal,	   // Only reuse existing handles (Stealthiest, might fail)
	HijackWithFallback // Try to reuse, OpenProcess if failed (Robust)
};

/**
 * Global configuration
 */
constexpr bool COPY_AND_DELETE = true;			      // Whether to copy the legitimate DLL to the TEMP folder and delete it after injection (Mostly for System32 Dll's)
const std::wstring TARGET = L"dummy.exe";			  // Target process name


/**
 * VendettaStager configuration
 */
constexpr auto CORE_INJECTION_METHOD = CoreInjectionMethod::LoadLibraryInjection; // Method to inject VendettaCore.dll into the target process
constexpr bool FIND_HANDLE_TO_TARGET = false;                                     // Whether to find and log which processes hold handles to the target process
const std::string VENDETTA_NAME = "VendettaCore.dll";                             // VendettaCore DLL name from the build
constexpr auto PROXY_TARGET = ProxyTarget::Svchost;								  // Method to select the target process for the proxy

/**
 * VendettaCore configuration
*/
const std::wstring BENIGN_DLL = LR"(C:\Windows\System32\xpsservices.dll)"; // Legitimate DLL path (This becomes the Phantom Dll)
constexpr auto HANDLE_ACQUISITION_MODE = HandleMode::HijackWithFallback;   // Method to acquire a handle to the target process
