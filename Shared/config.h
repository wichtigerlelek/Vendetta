#pragma once

constexpr std::string VENDETTA_VERSION = "1.3.5 alpha";

const std::wstring TARGET = L"dummy.exe"; // Target process name
const std::string VENDETTA_NAME = "VendettaCore.dll"; // VendettaCore DLL name
const std::wstring BENIGN_DLL = LR"(C:\Windows\System32\xpsservices.dll)"; //Legitimate DLL path (This becomes the Phantom Dll)
// (Necessary for System32 Dll's because they are owned by TrustedInstaller)
constexpr bool COPY_AND_DELETE = true;// Whether to copy the legitimate DLL to the TEMP folder and delete it after injection