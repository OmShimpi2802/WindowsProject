#pragma once
#include <string>

class Policymanager
{
private:
	static bool allowcopy;
	static bool allowpaste;
	static bool allowcut;
	static bool allowprintscreen;
	static bool allowfilesave;
	static bool logevents;
public:
	static bool LoadPolicy(const std::string& ConfigPath);
	static bool IsCopyAllowed();
	static bool IsPasteAllowed();
	static bool IsCutAllowed();
	static bool IsPrintScreenAllowed();
	static bool IsFileSaveAllowed();
	static bool ShouldLogEvents();
};
