#include <windows.h>
#include <psapi.h>
#include <winternl.h>
#include <sddl.h>
#include <userenv.h>
#include <cstdint>
#define _NTDEF_
#include <ntsecapi.h>
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Secur32.lib")

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

PTOKEN_PRIVILEGES generate_privilege(const uint64_t& priv)
{
	const DWORD privilege_count = count_one(priv);
	const DWORD size = sizeof(DWORD) + sizeof(LUID_AND_ATTRIBUTES) * privilege_count;
	auto privileges = static_cast<PTOKEN_PRIVILEGES>(LocalAlloc(LPTR, size));
	if (!privileges) return nullptr;
	privileges->PrivilegeCount = privilege_count;
	for (DWORD i = 0, j = 0; i < 64; ++i)
	{
		if (priv & static_cast<uint64_t>(1) << i)
		{
			privileges->Privileges[j].Attributes = SE_PRIVILEGE_ENABLED;
			privileges->Privileges[j++].Luid.LowPart = i + 1;
			if (j >= privilege_count) break;
		}
	}
	return privileges;
}

PTOKEN_GROUPS generate_groups(const PSID& logon_sid)
{
	DWORD group_count = 12;
	if (logon_sid) group_count++;
	const DWORD size = sizeof(DWORD) + sizeof(SID_AND_ATTRIBUTES) * group_count;
	auto groups = static_cast<PTOKEN_GROUPS>(LocalAlloc(LPTR, size));
	if (!groups) return nullptr;
	groups->GroupCount = group_count;
	ConvertStringSidToSidA("S-1-16-16384", &groups->Groups[0].Sid); //Mandatory Label\System Mandatory Level Label
	groups->Groups[0].Attributes = SE_GROUP_INTEGRITY_ENABLED | SE_GROUP_INTEGRITY;
	ConvertStringSidToSidA("S-1-1-0", &groups->Groups[1].Sid); //Everyone
	groups->Groups[1].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	//NT AUTHORITY\Local account and member of Administrators group
	ConvertStringSidToSidA("S-1-5-114", &groups->Groups[2].Sid);
	groups->Groups[2].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	ConvertStringSidToSidA("S-1-5-11", &groups->Groups[3].Sid); //NT AUTHORITY\Authenticated Users
	groups->Groups[3].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	ConvertStringSidToSidA("S-1-5-32-545", &groups->Groups[4].Sid); //BUILTIN\Users
	groups->Groups[4].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	ConvertStringSidToSidA("S-1-2-1", &groups->Groups[5].Sid); //CONSOLE LOGON
	groups->Groups[5].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	ConvertStringSidToSidA("S-1-5-4", &groups->Groups[6].Sid); //NT AUTHORITY\INTERACTIVE
	groups->Groups[6].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	ConvertStringSidToSidA("S-1-5-113", &groups->Groups[7].Sid); //NT AUTHORITY\Local account
	groups->Groups[7].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	ConvertStringSidToSidA("S-1-2-0", &groups->Groups[8].Sid); //LOCAL
	groups->Groups[8].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	ConvertStringSidToSidA("S-1-5-15", &groups->Groups[9].Sid); //NT AUTHORITY\This Organization
	groups->Groups[9].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	ConvertStringSidToSidA("S-1-5-32-544", &groups->Groups[10].Sid); //BUILTIN\Administrators
	groups->Groups[10].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY |
		SE_GROUP_OWNER;
	//NT SERVICE\TrustedInstaller
	ConvertStringSidToSidA("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &groups->Groups[11].Sid);
	groups->Groups[11].Attributes = SE_GROUP_ENABLED;
	if (logon_sid)
	{
		groups->Groups[12].Sid = logon_sid;
		groups->Groups[12].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY |
			SE_GROUP_LOGON_ID;
	}
	return groups;
}

void free_groups(PTOKEN_GROUPS groups)
{
	for (DWORD i = 0; i < groups->GroupCount; ++i) LocalFree(groups->Groups[i].Sid);
	LocalFree(groups);
}

LPVOID get_token_info(HANDLE token, TOKEN_INFORMATION_CLASS type)
{
	DWORD length;
	LPVOID buf = nullptr;
	GetTokenInformation(token, type, nullptr, 0, &length);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		buf = static_cast<LPVOID>(LocalAlloc(LPTR, length));
		GetTokenInformation(token, type, buf, length, &length);
	}
	return buf;
}

void enable_all_privileges(HANDLE token)
{
	auto privileges = static_cast<PTOKEN_PRIVILEGES>(get_token_info(token, TokenPrivileges));
	if (privileges)
	{
		for (DWORD i = 0; i < privileges->PrivilegeCount; ++i)
			privileges->Privileges[i].Attributes =
				SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(token, false, privileges, 0, NULL, NULL);
		LocalFree(privileges);
	}
}

PSID get_logon_sid(HANDLE token)
{
	PSID logon_sid = nullptr;
	auto groups = static_cast<PTOKEN_GROUPS>(get_token_info(token, TokenGroups));
	if (!groups) return nullptr;
	for (DWORD i = 0; i < groups->GroupCount; ++i)
		if (groups->Groups[i].Attributes & SE_GROUP_LOGON_ID)
		{
			DWORD length = GetLengthSid(groups->Groups[i].Sid);
			logon_sid = static_cast<PSID>(LocalAlloc(LPTR, length));
			if (!logon_sid) break;
			if (!CopySid(length, logon_sid, groups->Groups[i].Sid))
			{
				LocalFree(logon_sid);
				logon_sid = nullptr;
			}
			break;
		}
	LocalFree(groups);
	return logon_sid;
}

LUID get_auth_id(const PSID uid, const DWORD session_id)
{
	ULONG session_count;
	PLUID session_list;
	LUID auth_id = SYSTEM_LUID;
	BOOL should_break;
	if (LsaEnumerateLogonSessions(&session_count, &session_list)) return auth_id;
	for (ULONG i = 0; i < session_count; ++i)
	{
		PSECURITY_LOGON_SESSION_DATA session_data;
		LsaGetLogonSessionData(&session_list[i], &session_data);
		if (session_data->Sid && EqualSid(session_data->Sid, uid))
		{
			auth_id = session_data->LogonId;
			should_break = session_id == session_data->Session;
		}
		else should_break = false;
		LsaFreeReturnBuffer(session_data);
		if (should_break) break;
	}
	LsaFreeReturnBuffer(session_list);
	return auth_id;
}

BOOL GetTokenFromPID(DWORD& ProcessId, PHANDLE TokenHandle)
{
	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
	if (!process) return false;
	BOOL res = OpenProcessToken(process, MAXIMUM_ALLOWED, TokenHandle);
	CloseHandle(process);
	return res;
}

DWORD GetLsassPid()
{
	SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
	SERVICE_STATUS_PROCESS status;
	DWORD bytes_needed = sizeof(status);
	DWORD pid = -1;
	if (!scm) return -1;
	SC_HANDLE service = OpenServiceA(scm, "SamSs", SERVICE_QUERY_STATUS);
	if (!service)
	{
		CloseServiceHandle(scm);
		return -1;
	}
	if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status),
	                         sizeof(status), &bytes_needed))
	{
		if (SERVICE_STOPPED != status.dwCurrentState) pid = status.dwProcessId;
	}
	CloseServiceHandle(service);
	CloseServiceHandle(scm);
	return pid;
}

HANDLE create_token(const PSID& uid, const uint64_t& priv_present, const PSID& logon_sid, LUID authid)
{
	auto const ZwCreateToken = reinterpret_cast<_ZwCreateToken>(GetProcAddress(LoadLibraryA("ntdll"), "ZwCreateToken"));
	if (!ZwCreateToken) return nullptr;
	SECURITY_QUALITY_OF_SERVICE sqos = {sizeof(sqos), SecurityDelegation, SECURITY_STATIC_TRACKING, FALSE};
	OBJECT_ATTRIBUTES oa = {sizeof(oa), 0, 0, 0, 0, &sqos};
	LARGE_INTEGER li = {{0xFFFFFFFF, -1}};
	TOKEN_USER user = {{uid, 0}};
	TOKEN_SOURCE source = {{'F', 'r', 'e', 'e', 'H', 'K', 0}, {0x99996E2F, 0x51495FA9}};
	TOKEN_OWNER owner = {uid};
	TOKEN_PRIMARY_GROUP primary_group;
	PTOKEN_GROUPS groups = generate_groups(logon_sid);
	PTOKEN_PRIVILEGES privileges = generate_privilege(priv_present);
	PSECURITY_DESCRIPTOR sd;
	ConvertStringSecurityDescriptorToSecurityDescriptorA("G:BAD:(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &sd,
	                                                     nullptr);
	TOKEN_DEFAULT_DACL default_dacl;
	BOOL present = false, defaulted = false;
	GetSecurityDescriptorDacl(sd, &present, &default_dacl.DefaultDacl, &defaulted);
	GetSecurityDescriptorGroup(sd, &primary_group.PrimaryGroup, &defaulted);
	HANDLE elevated_token = nullptr;
	ZwCreateToken(&elevated_token, TOKEN_ALL_ACCESS, &oa, TokenPrimary, &authid, &li, &user, groups, privileges,
	              &owner, &primary_group, &default_dacl, &source);
	LocalFree(sd);
	LocalFree(privileges);
	free_groups(groups);
	return elevated_token;
}

LPWSTR expand_environment(LPCWSTR src)
{
	DWORD char_count = ExpandEnvironmentStringsW(src, nullptr, 0);
	if (!char_count) return nullptr;
	auto dst = static_cast<LPWSTR>(LocalAlloc(LPTR, char_count * sizeof(WCHAR)));
	if (!dst) return nullptr;
	if (char_count == ExpandEnvironmentStringsW(src, dst, char_count)) return dst;
	LocalFree(dst);
	return nullptr;
}

LPWSTR current_directory()
{
	DWORD char_count = GetCurrentDirectoryW(0, nullptr);
	if (!char_count) return nullptr;
	auto dst = static_cast<LPWSTR>(LocalAlloc(LPTR, char_count * sizeof(WCHAR)));
	if (!dst) return nullptr;
	if (char_count == GetCurrentDirectoryW(char_count, dst) + 1) return dst;
	LocalFree(dst);
	return nullptr;
}

int main()
{
	int argc;
	LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	HANDLE CurrentProcessToken = INVALID_HANDLE_VALUE;
	HANDLE OriginalLsassProcessToken = INVALID_HANDLE_VALUE;
	HANDLE SystemToken = INVALID_HANDLE_VALUE;
	DWORD session_id = -1, LsassPid = GetLsassPid();
	DWORD ReturnLength = 0;
	uint64_t priv_present = 0xFFFFFFFFE;
	PSID uid;
	if (argc > 1) ConvertStringSidToSidW(argv[1], &uid);
	else ConvertStringSidToSidA("S-1-5-18", &uid);
	if (LsassPid == -1) return -1;
	if (!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &CurrentProcessToken)) return -2;
	enable_all_privileges(CurrentProcessToken);
	GetTokenInformation(CurrentProcessToken, TokenSessionId, &session_id, sizeof(DWORD), &ReturnLength);
	LUID authid = get_auth_id(uid, session_id);
	PSID logon_sid = get_logon_sid(CurrentProcessToken);
	CloseHandle(CurrentProcessToken);
	if (session_id == -1) return -3;
	if (!GetTokenFromPID(LsassPid, &OriginalLsassProcessToken)) return -4;
	BOOL res = DuplicateTokenEx(OriginalLsassProcessToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation,
	                            TokenImpersonation, &SystemToken);
	CloseHandle(OriginalLsassProcessToken);
	if (!res) return -5;
	enable_all_privileges(SystemToken);
	res = SetThreadToken(NULL, SystemToken);
	CloseHandle(SystemToken);
	if (!res) return -6;
	HANDLE token = create_token(uid, priv_present, logon_sid, authid);
	LocalFree(uid);
	if (!token) return -7;
	SetTokenInformation(token, TokenSessionId, static_cast<PVOID>(&session_id), sizeof(DWORD));
	STARTUPINFOW startup_info = {sizeof(STARTUPINFOW)};
	startup_info.lpDesktop = const_cast<LPWSTR>(L"WinSta0\\Default");
	startup_info.dwFlags = STARTF_USESHOWWINDOW;
	startup_info.wShowWindow = SW_SHOWDEFAULT;
	PROCESS_INFORMATION process_info = {0};
	LPVOID lpEnvironment = nullptr;
	CreateEnvironmentBlock(&lpEnvironment, token, TRUE);
	LPWSTR working_directory = current_directory();
	LPWSTR cmdline = expand_environment(L"%SYSTEMROOT%\\System32\\cmd.exe /K");
	res = CreateProcessAsUserW(token, NULL, cmdline, NULL, NULL, false, CREATE_UNICODE_ENVIRONMENT, lpEnvironment,
	                           working_directory, &startup_info, &process_info);
	if (res) WaitForSingleObjectEx(process_info.hThread, 0, false);
	LocalFree(cmdline);
	LocalFree(working_directory);
	CloseHandle(token);
	DestroyEnvironmentBlock(lpEnvironment);
	if (!res) return -8;
	CloseHandle(process_info.hThread);
	WaitForSingleObjectEx(process_info.hProcess, INFINITE, false);
	CloseHandle(process_info.hProcess);
	return 0;
}
