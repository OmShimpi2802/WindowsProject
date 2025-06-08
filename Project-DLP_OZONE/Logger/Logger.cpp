#include "pch.h"
#include "framework.h"
#include "Logger.h"
#include <fstream>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <sstream>

static std::string LogFilePath;

void Logger::Init(const std::string& Logpath)
{
	LogFilePath = Logpath;
}

void Logger::Log(const std::string& message)
{
	if (LogFilePath.empty())
		return;

	std::ofstream logFile(LogFilePath, std::ios::app);
	if (!logFile.is_open())
		return;
	auto now = std::chrono::system_clock::now();
	auto in_time = std::chrono::system_clock::to_time_t(now);
	std::tm timeinfo;
	localtime_s(&timeinfo, &in_time);

	std::ostringstream oss;
	oss << "[" << std::put_time(&timeinfo, "%Y-%m-%d %H:%M:%S") << "] ";
	oss << message << "\n";

	logFile << oss.str();
	logFile.close();
}
