#pragma once
constexpr std::string VENDETTA_VERSION = "1.3.2 alpha";

const std::wstring TARGET = L"dummy.exe"; // Target process name
constexpr auto VENDETTA_PATH = R"(C:\Users\felix\Documents\Projects\Vendetta\build\VendettaCore.dll)"; // Path to VendettaCore DLL
constexpr auto VENDETTA_NAME = std::string_view(VENDETTA_PATH).substr(std::string_view(VENDETTA_PATH).find_last_of(R"(\/)") + 1); // VendettaCore DLL name for unloading
const std::wstring BENIGN_DLL = LR"(C:\Users\felix\Documents\Projects\Vendetta\dummy\GameOverlayRenderer64.dll)"; // Legitimate DLL path (This becomes the Phantom Dll)