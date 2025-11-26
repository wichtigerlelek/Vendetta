#pragma once
#include <filesystem>
constexpr std::string VENDETTA_VERSION = "1.3.4 alpha";

const std::wstring TARGET = L"dummy.exe"; // Target process name
const std::string VENDETTA_NAME = "VendettaCore.dll"; // VendettaCore DLL name
const std::wstring BENIGN_DLL = LR"(C:\Windows\System32\xpsservices.dll)"; // Legitimate DLL path (This becomes the Phantom Dll)