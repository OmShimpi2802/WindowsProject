#pragma once
#include <string>

class Logger
{
public:
	static void Init(const std::string& Logpath);
	static void Log(const std::string& message);
};
