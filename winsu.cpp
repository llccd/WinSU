#include <windows.h>
#include <psapi.h>
#include <winternl.h>
#include <sddl.h>
#include <userenv.h>
#include <cstdint>
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Userenv.lib")

typedef NTSTATUS (NTAPI* _ZwCreateToken)(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN TOKEN_TYPE Type,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_OWNER Owner,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl,
	IN PTOKEN_SOURCE Source
);

DWORD count_one(uint64_t x)
{
	x = (x & 0x5555555555555555) + (x >> 1 & 0x5555555555555555);
	x = (x & 0x3333333333333333) + (x >> 2 & 0x3333333333333333);
	x = (x & 0x0f0f0f0f0f0f0f0f) + (x >> 4 & 0x0f0f0f0f0f0f0f0f);
	x = (x & 0x00ff00ff00ff00ff) + (x >> 8 & 0x00ff00ff00ff00ff);
	x = (x & 0x0000ffff0000ffff) + (x >> 16 & 0x0000ffff0000ffff);
	x = (x & 0x00000000ffffffff) + (x >> 32 & 0x00000000ffffffff);
	return static_cast<DWORD>(x);
}

PTOKEN_PRIVILEGES GeneratePrivilege(const uint64_t& priv)
{
	const DWORD NumOfPrivileges = count_one(priv);
	const DWORD nBufferSize = sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES) * NumOfPrivileges;
	auto privileges = static_cast<PTOKEN_PRIVILEGES>(LocalAlloc(LPTR, nBufferSize));
	if (!privileges) return nullptr;
	privileges->PrivilegeCount = NumOfPrivileges;
	for (DWORD i = 0, j = 0; i < 64; ++i)
	{
		if (priv & static_cast<uint64_t>(1) << i)
		{
			privileges->Privileges[j].Attributes = SE_PRIVILEGE_ENABLED;
			privileges->Privileges[j++].Luid.LowPart = i + 1;
			if (j >= NumOfPrivileges) break;
		}
	}
	return privileges;
}

PTOKEN_GROUPS GenerateGroups()
{
	const DWORD NumOfGroups = 9;
	const DWORD nBufferSize = sizeof(TOKEN_GROUPS) + sizeof(SID_AND_ATTRIBUTES) * NumOfGroups;
	auto groups = static_cast<PTOKEN_GROUPS>(LocalAlloc(LPTR, nBufferSize));
	if (!groups) return nullptr;
	groups->GroupCount = NumOfGroups;
	ConvertStringSidToSidA("S-1-5-32-544", &groups->Groups[0].Sid); //BUILTIN\Administrators
	groups->Groups[0].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY | SE_GROUP_OWNER;
	ConvertStringSidToSidA("S-1-1-0", &groups->Groups[1].Sid); //Everyone
	groups->Groups[1].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	ConvertStringSidToSidA("S-1-16-16384", &groups->Groups[2].Sid); //Mandatory Label\System Mandatory Level Label
	groups->Groups[2].Attributes = SE_GROUP_INTEGRITY_ENABLED | SE_GROUP_INTEGRITY;
	ConvertStringSidToSidA("S-1-5-11", &groups->Groups[3].Sid); //NT AUTHORITY\Authenticated Users
	groups->Groups[3].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	//NT SERVICE\TrustedInstaller
	ConvertStringSidToSidA("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &groups->Groups[4].Sid);
	groups->Groups[4].Attributes = SE_GROUP_ENABLED;
	ConvertStringSidToSidA("S-1-2-1", &groups->Groups[5].Sid); //CONSOLE LOGON
	groups->Groups[5].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	ConvertStringSidToSidA("S-1-5-4", &groups->Groups[6].Sid); //NT AUTHORITY\INTERACTIVE
	groups->Groups[6].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	ConvertStringSidToSidA("S-1-2-0", &groups->Groups[7].Sid); //LOCAL
	groups->Groups[7].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	ConvertStringSidToSidA("S-1-5-15", &groups->Groups[8].Sid); //NT AUTHORITY\This Organization
	groups->Groups[8].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	return groups;
}

void FreeGroups(PTOKEN_GROUPS groups)
{
	for (DWORD i = 0; i < groups->GroupCount; ++i) LocalFree(groups->Groups[i].Sid);
	LocalFree(groups);
}

LPVOID GetInfoFromToken(HANDLE hToken, TOKEN_INFORMATION_CLASS type)
{
	DWORD dwLengthNeeded;
	LPVOID lpData = nullptr;
	GetTokenInformation(hToken, type, nullptr, 0, &dwLengthNeeded);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		lpData = static_cast<LPVOID>(LocalAlloc(LPTR, dwLengthNeeded));
		GetTokenInformation(hToken, type, lpData, dwLengthNeeded, &dwLengthNeeded);
	}
	return lpData;
}

void EnableAllPrivileges(HANDLE TokenHandle)
{
	auto Privileges = static_cast<PTOKEN_PRIVILEGES>(GetInfoFromToken(TokenHandle, TokenPrivileges));
	if (Privileges)
	{
		for (DWORD i = 0; i < Privileges->PrivilegeCount; ++i)
			Privileges->Privileges[i].Attributes =
				SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(TokenHandle, false, Privileges, 0, NULL, NULL);
		LocalFree(Privileges);
	}
}

BOOL GetTokenFromPID(DWORD& ProcessId, PHANDLE TokenHandle)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
	if (!hProcess) return false;
	BOOL res = OpenProcessToken(hProcess, MAXIMUM_ALLOWED, TokenHandle);
	CloseHandle(hProcess);
	return res;
}

DWORD GetLsassPid()
{
	SC_HANDLE schSCManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
	SERVICE_STATUS_PROCESS ServiceStatus;
	DWORD dwBytesNeeded = sizeof(ServiceStatus);
	DWORD ProcessId = -1;
	if (!schSCManager) return -1;
	SC_HANDLE schService = OpenServiceA(schSCManager, "SamSs", SERVICE_QUERY_STATUS);
	if (!schService)
	{
		CloseServiceHandle(schSCManager);
		return -1;
	}
	if (QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ServiceStatus),
	                         sizeof(ServiceStatus), &dwBytesNeeded))
	{
		if (SERVICE_STOPPED != ServiceStatus.dwCurrentState) ProcessId = ServiceStatus.dwProcessId;
	}
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	return ProcessId;
}

HANDLE CreateUserToken(const PSID& uid, const uint64_t& priv_present)
{
	auto const ZwCreateToken = reinterpret_cast<_ZwCreateToken>(GetProcAddress(LoadLibraryA("ntdll"), "ZwCreateToken"));
	if (!ZwCreateToken) return nullptr;
	SECURITY_QUALITY_OF_SERVICE sqos = {sizeof(sqos), SecurityDelegation, SECURITY_STATIC_TRACKING, FALSE};
	OBJECT_ATTRIBUTES oa = {sizeof(oa), 0, 0, 0, 0, &sqos};
	LUID authid = SYSTEM_LUID;
	LARGE_INTEGER li = {{0xFFFFFFFF, -1}};
	TOKEN_USER userToken = {{uid, 0}};
	TOKEN_SOURCE sourceToken = {{'F', 'r', 'e', 'e', 'H', 'K', 0}, {0x99996E2F, 0x51495FA9}};
	TOKEN_OWNER owner = {uid};
	TOKEN_PRIMARY_GROUP primary_group;
	PTOKEN_GROUPS groups = GenerateGroups();
	PTOKEN_PRIVILEGES privileges = GeneratePrivilege(priv_present);
	PSECURITY_DESCRIPTOR sd;
	ConvertStringSecurityDescriptorToSecurityDescriptorA("G:BAD:(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &sd,
	                                                     nullptr);
	TOKEN_DEFAULT_DACL default_dacl;
	BOOL bPresent = false, bDefaulted = false;
	GetSecurityDescriptorDacl(sd, &bPresent, &default_dacl.DefaultDacl, &bDefaulted);
	GetSecurityDescriptorGroup(sd, &primary_group.PrimaryGroup, &bDefaulted);
	HANDLE elevated_token = nullptr;
	ZwCreateToken(&elevated_token, TOKEN_ALL_ACCESS, &oa, TokenPrimary, &authid, &li, &userToken, groups, privileges,
	              &owner, &primary_group, &default_dacl, &sourceToken);
	LocalFree(sd);
	LocalFree(privileges);
	FreeGroups(groups);
	return elevated_token;
}

LPWSTR ExpandEnvironment(LPCWSTR Src)
{
	DWORD nSize = ExpandEnvironmentStringsW(Src, NULL, 0);
	if (!nSize) return nullptr;
	auto Dest = static_cast<LPWSTR>(LocalAlloc(LPTR, nSize));
	if (!Dest) return nullptr;
	if (nSize == ExpandEnvironmentStringsW(Src, Dest, nSize)) return Dest;
	LocalFree(Dest);
	return nullptr;
}

LPWSTR CurrentDirectory()
{
	DWORD nSize = GetCurrentDirectoryW(0, NULL);
	if (!nSize) return nullptr;
	auto Dest = static_cast<LPWSTR>(LocalAlloc(LPTR, nSize));
	if (!Dest) return nullptr;
	if (nSize == GetCurrentDirectoryW(nSize, Dest) + 1) return Dest;
	LocalFree(Dest);
	return nullptr;
}

int main()
{
	int argc;
	LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	HANDLE CurrentProcessToken = INVALID_HANDLE_VALUE;
	HANDLE OriginalLsassProcessToken = INVALID_HANDLE_VALUE;
	HANDLE SystemToken = INVALID_HANDLE_VALUE;
	DWORD SessionID = -1, LsassPid = GetLsassPid();
	DWORD ReturnLength = 0;
	uint64_t priv_present = 0xFFFFFFFFE;
	PSID uid;
	if (argc > 1) ConvertStringSidToSidW(argv[1], &uid);
	else ConvertStringSidToSidA("S-1-5-18", &uid);
	if (LsassPid == -1) return -1;
	if (!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &CurrentProcessToken)) return -2;
	EnableAllPrivileges(CurrentProcessToken);
	GetTokenInformation(CurrentProcessToken, TokenSessionId, &SessionID, sizeof(DWORD), &ReturnLength);
	CloseHandle(CurrentProcessToken);
	if (SessionID == -1) return -3;
	if (!GetTokenFromPID(LsassPid, &OriginalLsassProcessToken)) return -4;
	BOOL res = DuplicateTokenEx(OriginalLsassProcessToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation,
	                            TokenImpersonation, &SystemToken);
	CloseHandle(OriginalLsassProcessToken);
	if (!res) return -5;
	EnableAllPrivileges(SystemToken);
	res = SetThreadToken(NULL, SystemToken);
	CloseHandle(SystemToken);
	if (!res) return -6;
	HANDLE hToken = CreateUserToken(uid, priv_present);
	LocalFree(uid);
	if (!hToken) return -7;
	SetTokenInformation(hToken, TokenSessionId, static_cast<PVOID>(&SessionID), sizeof(DWORD));
	STARTUPINFOW StartupInfo = {sizeof(STARTUPINFOW)};
	StartupInfo.lpDesktop = const_cast<LPWSTR>(L"WinSta0\\Default");
	StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
	StartupInfo.wShowWindow = SW_SHOWDEFAULT;
	PROCESS_INFORMATION ProcessInfo = {0};
	LPVOID lpEnvironment = nullptr;
	CreateEnvironmentBlock(&lpEnvironment, hToken, TRUE);
	LPWSTR WorkingDirectory = CurrentDirectory();
	LPWSTR cmdline = ExpandEnvironment(L"%SYSTEMROOT%\\System32\\cmd.exe /K");
	CreateProcessAsUserW(hToken, NULL, cmdline, NULL, NULL, false, CREATE_UNICODE_ENVIRONMENT, lpEnvironment,
	                     WorkingDirectory, &StartupInfo, &ProcessInfo);
	WaitForSingleObjectEx(ProcessInfo.hProcess, 0, false);
	LocalFree(cmdline);
	LocalFree(WorkingDirectory);
	CloseHandle(hToken);
	DestroyEnvironmentBlock(lpEnvironment);
	WaitForSingleObjectEx(ProcessInfo.hProcess, INFINITE, false);
	CloseHandle(ProcessInfo.hProcess);
	CloseHandle(ProcessInfo.hThread);
	return 0;
}
