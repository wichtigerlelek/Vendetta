#pragma once
#include <phnt_windows.h>
#include <print>
#include <chrono>

enum LogType : uint8_t
{
    LogInfo,
    LogWarn,
    LogWarnTest,
    LogError
};

constexpr std::string_view RESET = "\033[0m";
constexpr std::string_view GREEN = "\033[1;32m";
constexpr std::string_view YELLOW = "\033[1;33m";
constexpr std::string_view RED = "\033[1;31m";


inline std::string GetTime() {
    auto const time = std::chrono::current_zone()->to_local(std::chrono::system_clock::now());
    return std::format("{:%H:%M:%S}", time);
}

template <typename... Args>
void Log(const LogType logType, std::format_string<Args...> fmt, Args&&... args)
{
    std::string_view label;
    std::string_view color;
    FILE* stream = stdout;

    switch (logType)
    {
    case LogInfo:
        color = GREEN;
        label = "[INFO] ";
        stream = stdout;
        break;
    case LogWarn:
        color = YELLOW;
        label = "[WARN] ";
        stream = stderr;
        break;
    case LogWarnTest:
        color = YELLOW;
        label = "[WARN TESTING] ";
        stream = stderr;
        break;
    case LogError:
        color = RED;
        label = "[ERR]  ";
        stream = stderr;
        break;
    }

    std::string timestamp = GetTime();
    std::string userMessage = std::format(fmt, std::forward<Args>(args)...);

    std::string msg = std::format("[{}] {} {}", timestamp, label, userMessage);

    #ifdef _WINDLL
    msg += '\n';
    OutputDebugStringA(msg.c_str());
    #else
    std::println(stream, "[{}] {} {}{}{}",
        timestamp,
        color,
        label,
        userMessage,
        RESET
    );
    #endif
}