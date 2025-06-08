// PolicyManager.cpp : Defines the functions for the static library.
//

#include "pch.h"
#include "framework.h"
#include "PolicyManager.h"
#include <fstream>
#include <iostream>
#include "json.hpp" // nlohmann/json

using json = nlohmann::json;

bool Policymanager::allowcopy = true;
bool Policymanager::allowpaste = true;
bool Policymanager::allowcut = true;
bool Policymanager::allowprintscreen = true;
bool Policymanager::allowfilesave = true;
bool Policymanager::logevents = false;

bool Policymanager::LoadPolicy(const std::string& ConfigPath)
{
	std::ifstream configfile(ConfigPath);
	if (!configfile.is_open())
	{
		std::cerr << "[PolicyManager] Failed to open config file.\n";
		return false;
	}

	try
	{
		json configjson;
		configfile >> configjson;
		allowcopy = configjson.value("allow_copy", true);
		allowpaste = configjson.value("allow_paste", true);
		allowcut = configjson.value("allow_cut", true);
		allowprintscreen = configjson.value("allow_printscreen", true);
		allowfilesave = configjson.value("allow_filesave", true);
		logevents = configjson.value("log_events", false);
		std::cout << "[PolicyManager] Policy Loaded , allow_copy :" << allowcopy <<" , allow_paste :"<< allowpaste << " , allow_cut :" << allowcut<< " , allow_printscreen :" << allowprintscreen << " , allow_filesave :" << allowfilesave << " , log_events :" << logevents << std::endl;
		return true;
	}
	catch(const std::exception& e)
	{
		std::cerr << "[PolicyManager] Error Passing Config " << e.what() << std::endl;
		return false;
	}

}

bool Policymanager::IsCopyAllowed()
{
	LoadPolicy("D:\\DLP-Notepad-Protector\\HookingEngine\\config.json");
	return allowcopy;
}

bool Policymanager::IsPasteAllowed()
{
	LoadPolicy("D:\\DLP-Notepad-Protector\\HookingEngine\\config.json");
	return allowpaste;
}

bool Policymanager::IsCutAllowed()
{
	LoadPolicy("D:\\DLP-Notepad-Protector\\HookingEngine\\config.json");
	return allowcut;
}

bool Policymanager::IsPrintScreenAllowed()
{
	LoadPolicy("D:\\DLP-Notepad-Protector\\HookingEngine\\config.json");
	return allowprintscreen;
}

bool Policymanager::IsFileSaveAllowed()
{
	LoadPolicy("D:\\DLP-Notepad-Protector\\HookingEngine\\config.json");
	return allowfilesave;
}

bool Policymanager::ShouldLogEvents()
{
	return logevents;
}
