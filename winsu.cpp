#include <windows.h>
#include <psapi.h>
#include <winternl.h>
#include <sddl.h>
#include <userenv.h>
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
typedef wchar_t* (NTAPI* _wcsstr)(wchar_t* wcs1, const wchar_t* wcs2);
typedef unsigned __int64 (NTAPI* _wcstoui64_ntdll)(const wchar_t* strSource, wchar_t** endptr, int base);
typedef unsigned long (NTAPI* _wcstoul)(const wchar_t* strSource, wchar_t** endptr, int base);

_wcsstr wcsstr_ntdll;
_wcstoui64_ntdll wcstoui64_ntdll;
_wcstoul wcstoul_ntdll;
_ZwCreateToken ZwCreateToken;


DWORD count_one(unsigned __int64 x)
{
	x = (x & 0x5555555555555555) + (x >> 1 & 0x5555555555555555);
	x = (x & 0x3333333333333333) + (x >> 2 & 0x3333333333333333);
	x = (x & 0x0f0f0f0f0f0f0f0f) + (x >> 4 & 0x0f0f0f0f0f0f0f0f);
	x = (x & 0x00ff00ff00ff00ff) + (x >> 8 & 0x00ff00ff00ff00ff);
	x = (x & 0x0000ffff0000ffff) + (x >> 16 & 0x0000ffff0000ffff);
	x = (x & 0x00000000ffffffff) + (x >> 32 & 0x00000000ffffffff);
	return static_cast<DWORD>(x);
}

PTOKEN_PRIVILEGES generate_privilege(const unsigned __int64& priv)
{
	const DWORD privilege_count = count_one(priv);
	const DWORD size = sizeof(DWORD) + sizeof(LUID_AND_ATTRIBUTES) * privilege_count;
	auto privileges = static_cast<PTOKEN_PRIVILEGES>(LocalAlloc(LPTR, size));
	if (!privileges) return nullptr;
	privileges->PrivilegeCount = privilege_count;
	for (DWORD i = 0, j = 0; i < 64; ++i)
	{
		if (priv & static_cast<unsigned __int64>(1) << i)
		{
			privileges->Privileges[j].Attributes = SE_PRIVILEGE_ENABLED;
			privileges->Privileges[j++].Luid.LowPart = i + 1;
			if (j >= privilege_count) break;
		}
	}
	return privileges;
}

PTOKEN_GROUPS generate_groups(const PSID& logon_sid, PSID* add_groups, const DWORD& add_count, const PSID& mandatory)
{
	DWORD group_count = 12 + add_count;
	if (logon_sid) group_count++;
	const DWORD size = sizeof(DWORD) + sizeof(SID_AND_ATTRIBUTES) * group_count;
	auto groups = static_cast<PTOKEN_GROUPS>(LocalAlloc(LPTR, size));
	if (!groups) return nullptr;
	groups->GroupCount = group_count;
	groups->Groups[0].Sid = mandatory;
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
	DWORD i;
	for (i = 0; i < add_count; ++i)
	{
		groups->Groups[i + 12].Sid = add_groups[i];
		groups->Groups[i + 12].Attributes = SE_GROUP_ENABLED;
	}
	if (logon_sid)
	{
		groups->Groups[i + 12].Sid = logon_sid;
		groups->Groups[i + 12].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY |
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

BOOL get_token_pid(DWORD& ProcessId, PHANDLE TokenHandle)
{
	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
	if (!process) return false;
	BOOL res = OpenProcessToken(process, MAXIMUM_ALLOWED, TokenHandle);
	CloseHandle(process);
	return res;
}

DWORD get_lsass_pid()
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

BOOL load_ntdll()
{
	HMODULE ntdll = LoadLibraryA("ntdll");
	if (!ntdll) return false;
	ZwCreateToken = reinterpret_cast<_ZwCreateToken>(GetProcAddress(ntdll, "ZwCreateToken"));
	if (!ZwCreateToken) return false;
	wcsstr_ntdll = reinterpret_cast<_wcsstr>(GetProcAddress(ntdll, "wcsstr"));
	if (!wcsstr_ntdll) return false;
	wcstoui64_ntdll = reinterpret_cast<_wcstoui64_ntdll>(GetProcAddress(ntdll, "_wcstoui64"));
	if (!wcstoui64_ntdll) return false;
	wcstoul_ntdll = reinterpret_cast<_wcstoul>(GetProcAddress(ntdll, "wcstoul"));
	if (!wcstoul_ntdll) return false;
	return true;
}

HANDLE create_token(const PSID& uid, const unsigned __int64& priv_present, const PSID& logon_sid, LUID authid,
                    LPCWSTR dacl, PSID* add_groups, DWORD add_count, const PSID& mandatory)
{
	SECURITY_QUALITY_OF_SERVICE sqos = {sizeof(sqos), SecurityDelegation, SECURITY_STATIC_TRACKING, FALSE};
	OBJECT_ATTRIBUTES oa = {sizeof(oa), 0, 0, 0, 0, &sqos};
	LARGE_INTEGER li = {{0xFFFFFFFF, -1}};
	TOKEN_USER user = {{uid, 0}};
	TOKEN_SOURCE source = {{'F', 'r', 'e', 'e', 'H', 'K', 0}, {0x99996E2F, 0x51495FA9}};
	TOKEN_OWNER owner = {uid};
	TOKEN_PRIMARY_GROUP primary_group;
	PTOKEN_GROUPS groups = generate_groups(logon_sid, add_groups, add_count, mandatory);
	PTOKEN_PRIVILEGES privileges = generate_privilege(priv_present);
	PSECURITY_DESCRIPTOR sd;
	ConvertStringSecurityDescriptorToSecurityDescriptorW(dacl, SDDL_REVISION_1, &sd,
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
	LPWSTR current_cmdline = GetCommandLineW();
	LPWSTR* argv = CommandLineToArgvW(current_cmdline, &argc);
	if (!argv) return -9;
	if (!load_ntdll()) return -10;
	HANDLE token = INVALID_HANDLE_VALUE;
	HANDLE dup_token = INVALID_HANDLE_VALUE;
	DWORD session_id = -1, lsass_pid = get_lsass_pid();
	DWORD ReturnLength = 0;
	DWORD add_count = 0;
	PSID* add_groups = nullptr;
	unsigned __int64 priv_present = 0xFFFFFFFFE;
	PSID uid;
	LPCWSTR dacl = L"G:BAD:(A;;GA;;;SY)(A;;GA;;;BA)";
	LPCWSTR cmd = L"%ComSpec% /K";
	LPCWSTR user = L"S-1-5-18";
	LPCWSTR mandatory_str = L"S-1-16-16384";
	STARTUPINFOW startup_info = {sizeof(STARTUPINFOW)};
	startup_info.lpDesktop = const_cast<LPWSTR>(L"WinSta0\\Default");
	startup_info.dwFlags = STARTF_USESHOWWINDOW;
	startup_info.wShowWindow = SW_SHOWDEFAULT;
	DWORD creation_flags = CREATE_UNICODE_ENVIRONMENT;
	BOOL wait = true;
	for (int i = 1; i < argc; ++i)
	{
		if (!lstrcmpiW(argv[i], L"-acl"))
		{
			if (++i >= argc) return 1;
			dacl = argv[i];
		}
		else if (!lstrcmpiW(argv[i], L"-d"))
		{
			if (++i >= argc) return 1;
			startup_info.lpDesktop = argv[i];
		}
		else if (!lstrcmpiW(argv[i], L"-p"))
		{
			if (++i >= argc) return 1;
			priv_present = wcstoui64_ntdll(argv[i], nullptr, 16);
		}
		else if (!lstrcmpiW(argv[i], L"-s"))
		{
			if (++i >= argc) return 1;
			session_id = wcstoul_ntdll(argv[i], nullptr, 16);
		}
		else if (!lstrcmpiW(argv[i], L"-nw"))
		{
			wait = false;
		}
		else if (!lstrcmpiW(argv[i], L"-c"))
		{
			creation_flags |= CREATE_NEW_CONSOLE;
		}
		else if (!lstrcmpiW(argv[i], L"-m"))
		{
			if (++i >= argc) return 1;
			if (!lstrcmpiW(argv[i], L"UT")) mandatory_str = L"S-1-16-0";
			else if (!lstrcmpiW(argv[i], L"LW")) mandatory_str = L"S-1-16-4096";
			else if (!lstrcmpiW(argv[i], L"ME")) mandatory_str = L"S-1-16-8192";
			else if (!lstrcmpiW(argv[i], L"MP")) mandatory_str = L"S-1-16-8448";
			else if (!lstrcmpiW(argv[i], L"HI")) mandatory_str = L"S-1-16-12288";
			else if (!lstrcmpiW(argv[i], L"SI")) mandatory_str = L"S-1-16-16384";
			else mandatory_str = argv[i];
		}
		else if (!lstrcmpiW(argv[i], L"-g"))
		{
			if (++i >= argc) return 1;
			add_count = wcstoul_ntdll(argv[i], nullptr, 10);
			add_groups = static_cast<PSID*>(LocalAlloc(LPTR, add_count * sizeof(PSID)));
			for (DWORD j = 0; j < add_count; j++)
			{
				if (++i >= argc) return 1;
				ConvertStringSidToSidW(argv[i], &add_groups[j]);
			}
		}
		else if (!lstrcmpiW(argv[i], L"--"))
		{
			if (++i >= argc) break;
			cmd = wcsstr_ntdll(current_cmdline, L"--") + 2;
			while (cmd && *cmd == L' ') cmd++;
			break;
		}
		else user = argv[i];
	}
	if (!ConvertStringSidToSidW(user, &uid)) return -11;
	if (lsass_pid == -1) return -1;
	if (!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &token)) return -2;
	enable_all_privileges(token);
	if (session_id == -1) GetTokenInformation(token, TokenSessionId, &session_id, sizeof(DWORD),
	                                          &ReturnLength);
	LUID authid = get_auth_id(uid, session_id);
	PSID logon_sid = get_logon_sid(token);
	PSID mandatory;
	if (!ConvertStringSidToSidW(mandatory_str, &mandatory)) return -12;
	CloseHandle(token);
	if (session_id == -1) return -3;
	if (!get_token_pid(lsass_pid, &token)) return -4;
	BOOL ret = DuplicateTokenEx(token, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation,
	                            TokenImpersonation, &dup_token);
	CloseHandle(token);
	if (!ret) return -5;
	enable_all_privileges(dup_token);
	ret = SetThreadToken(nullptr, dup_token);
	CloseHandle(dup_token);
	if (!ret) return -6;
	token = create_token(uid, priv_present, logon_sid, authid, dacl, add_groups, add_count, mandatory);
	LocalFree(uid);
	if (!token) return -7;
	SetTokenInformation(token, TokenSessionId, static_cast<PVOID>(&session_id), sizeof(DWORD));
	PROCESS_INFORMATION process_info = {0};
	LPVOID lpEnvironment = nullptr;
	CreateEnvironmentBlock(&lpEnvironment, token, TRUE);
	LPWSTR working_directory = current_directory();
	LPWSTR cmdline = expand_environment(cmd);
	ret = CreateProcessAsUserW(token, NULL, cmdline, NULL, NULL, false, creation_flags, lpEnvironment,
	                           working_directory, &startup_info, &process_info);
	if (ret) WaitForSingleObjectEx(process_info.hThread, 0, false);
	LocalFree(cmdline);
	LocalFree(working_directory);
	CloseHandle(token);
	DestroyEnvironmentBlock(lpEnvironment);
	LocalFree(argv);
	if (!ret) return -8;
	CloseHandle(process_info.hThread);
	if (wait) WaitForSingleObjectEx(process_info.hProcess, INFINITE, false);
	CloseHandle(process_info.hProcess);
	return 0;
}
