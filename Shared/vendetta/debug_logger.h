#pragma once
#include <windows.h>
#include <string_view>
#include <chrono>
#include <format>

enum LogType : uint8_t
{
    LogInfo,
    LogWarn,
    LogWarnTest,
    LogError
};

inline std::string GetTime() {
    auto const time = std::chrono::current_zone()->to_local(std::chrono::system_clock::now());
    return std::format("{:%H:%M:%S}", time);
}

template <typename... Args>
void Log(const LogType logType, std::format_string<Args...> fmt, Args&&... args)
{
    std::string_view label;

    switch (logType)
    {
    case LogInfo:
        label = "[INFO]";
        break;
    case LogWarn:
        label = "[WARN]";
        break;
    case LogWarnTest:
        label = "[WARN TESTING]";
        break;
    case LogError:
        label = "[ERROR]";
        break;
    }

    std::string timestamp = GetTime();
    std::string userMessage = std::format(fmt, std::forward<Args>(args)...);
    std::string msg = std::format("[{}] {} {}",
        timestamp,
        label,
        userMessage
    );

    OutputDebugStringA(msg.c_str());
}