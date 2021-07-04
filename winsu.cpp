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

static _wcsstr wcsstr_ntdll;
static _wcstoui64_ntdll wcstoui64_ntdll;
static _wcstoul wcstoul_ntdll;
static _ZwCreateToken ZwCreateToken;

static SID Everyone = { 1, 1, {SECURITY_WORLD_SID_AUTHORITY}, {SECURITY_WORLD_RID} };
static SID Local = { 1, 1, {SECURITY_LOCAL_SID_AUTHORITY}, {SECURITY_LOCAL_RID} };
static SID ConsoleLogon = { 1, 1, {SECURITY_LOCAL_SID_AUTHORITY}, {SECURITY_LOCAL_LOGON_RID} };
static SID INTERACTIVE = { 1, 1, {SECURITY_NT_AUTHORITY}, {SECURITY_INTERACTIVE_RID} };
static SID AuthenticatedUsers = { 1, 1, {SECURITY_NT_AUTHORITY}, {SECURITY_AUTHENTICATED_USER_RID} };
static SID ThisOrganization = { 1, 1, {SECURITY_NT_AUTHORITY}, {SECURITY_THIS_ORGANIZATION_RID} };
static SID LocalAccount = { 1, 1, {SECURITY_NT_AUTHORITY}, {SECURITY_LOCAL_ACCOUNT_RID} };
static SID LocalAccountAndAdmin = { 1, 1, {SECURITY_NT_AUTHORITY}, {SECURITY_LOCAL_ACCOUNT_AND_ADMIN_RID} };
static SID mandatory = { 1, 1, {SECURITY_MANDATORY_LABEL_AUTHORITY}, {SECURITY_MANDATORY_SYSTEM_RID} };

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
	const DWORD size = FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges[privilege_count]);
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

PTOKEN_GROUPS generate_groups(const PSID& logon_sid, PSID* add_groups, const DWORD& add_count, const PSID& integrity)
{
	DWORD group_count = 12 + add_count;
	if (logon_sid) group_count++;
	const DWORD size = FIELD_OFFSET(TOKEN_GROUPS, Groups[group_count]);
	auto groups = static_cast<PTOKEN_GROUPS>(LocalAlloc(LPTR, size));
	if (!groups) return nullptr;
	groups->GroupCount = group_count;

	groups->Groups[0].Sid = integrity;
	groups->Groups[0].Attributes = SE_GROUP_INTEGRITY_ENABLED | SE_GROUP_INTEGRITY;
	groups->Groups[1].Sid = &Everyone;
	groups->Groups[1].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	groups->Groups[2].Sid = &Local;
	groups->Groups[2].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	groups->Groups[3].Sid = &AuthenticatedUsers;
	groups->Groups[3].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	groups->Groups[4].Sid = &ThisOrganization;
	groups->Groups[4].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	groups->Groups[5].Sid = &ConsoleLogon;
	groups->Groups[5].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	groups->Groups[6].Sid = &INTERACTIVE;
	groups->Groups[6].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	groups->Groups[7].Sid = &LocalAccount;
	groups->Groups[7].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	groups->Groups[8].Sid = &LocalAccountAndAdmin;
	groups->Groups[8].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	ConvertStringSidToSidA("S-1-5-32-545", &groups->Groups[9].Sid); //BUILTIN\Users
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
	for (DWORD i = 9; i < groups->GroupCount; ++i) LocalFree(groups->Groups[i].Sid);
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
			privileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;

		AdjustTokenPrivileges(token, false, privileges, 0, nullptr, nullptr);
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
			const auto length = GetLengthSid(groups->Groups[i].Sid);
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
	if (LsaEnumerateLogonSessions(&session_count, &session_list)) return auth_id;

	for (ULONG i = 0; i < session_count; ++i)
	{
		BOOL should_break;
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
	const auto process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
	if (!process) return false;
	const auto res = OpenProcessToken(process, MAXIMUM_ALLOWED, TokenHandle);
	CloseHandle(process);
	return res;
}

DWORD get_lsass_pid()
{
	const auto scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
	if (!scm) return -1;

	const auto service = OpenServiceA(scm, "SamSs", SERVICE_QUERY_STATUS);
	if (!service)
	{
		CloseServiceHandle(scm);
		return -1;
	}
	
	SERVICE_STATUS_PROCESS status;
	DWORD bytes_needed = sizeof(status);
	DWORD pid = -1;
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
	const auto ntdll = LoadLibraryA("ntdll");
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
	TOKEN_SOURCE source = { {'F', 'r', 'e', 'e', 'H', 'K', 0}, {0x99996E2F, 0x51495FA9} };
	TOKEN_USER user = {{uid, 0}};
	PTOKEN_GROUPS groups = generate_groups(logon_sid, add_groups, add_count, mandatory);
	PTOKEN_PRIVILEGES privileges = generate_privilege(priv_present);
	TOKEN_OWNER owner = {uid};

	PSECURITY_DESCRIPTOR sd;
	ConvertStringSecurityDescriptorToSecurityDescriptorW(dacl, SDDL_REVISION_1, &sd,
	                                                     nullptr);
	TOKEN_PRIMARY_GROUP primary_group;
	TOKEN_DEFAULT_DACL default_dacl;
	BOOL present = false, defaulted = false;
	GetSecurityDescriptorGroup(sd, &primary_group.PrimaryGroup, &defaulted);
	GetSecurityDescriptorDacl(sd, &present, &default_dacl.DefaultDacl, &defaulted);
	LocalFree(sd);

	HANDLE elevated_token = INVALID_HANDLE_VALUE;
	ZwCreateToken(&elevated_token, TOKEN_ALL_ACCESS, &oa, TokenPrimary, &authid, &li, &user, groups, privileges,
	              &owner, &primary_group, &default_dacl, &source);

	LocalFree(privileges);
	free_groups(groups);
	return elevated_token;
}

LPWSTR expand_environment(LPCWSTR src)
{
	const auto char_count = ExpandEnvironmentStringsW(src, nullptr, 0);
	if (!char_count) return nullptr;
	const auto dst = static_cast<LPWSTR>(LocalAlloc(LPTR, char_count * sizeof(WCHAR)));
	if (!dst) return nullptr;
	if (char_count == ExpandEnvironmentStringsW(src, dst, char_count)) return dst;
	LocalFree(dst);
	return nullptr;
}

LPWSTR current_directory()
{
	const auto char_count = GetCurrentDirectoryW(0, nullptr);
	if (!char_count) return nullptr;
	const auto dst = static_cast<LPWSTR>(LocalAlloc(LPTR, char_count * sizeof(WCHAR)));
	if (!dst) return nullptr;
	if (char_count == GetCurrentDirectoryW(char_count, dst) + 1) return dst;
	LocalFree(dst);
	return nullptr;
}

_declspec(noreturn) void main()
{
	if (!load_ntdll()) ExitProcess(0x100);

	int argc;
	const auto current_cmdline = GetCommandLineW();
	const auto argv = CommandLineToArgvW(current_cmdline, &argc);
	if (!argv) ExitProcess(0x101);

	auto user = L"S-1-5-18";
	auto cmd = L"%ComSpec% /K";
	auto dacl = L"G:BAD:(A;;GA;;;SY)(A;;GA;;;BA)";
	STARTUPINFOW startup_info = {sizeof(STARTUPINFOW)};
	startup_info.wShowWindow = SW_SHOWDEFAULT;
	startup_info.dwFlags = STARTF_USESHOWWINDOW;
	startup_info.lpDesktop = const_cast<LPWSTR>(L"WinSta0\\Default");
	DWORD creation_flags = CREATE_UNICODE_ENVIRONMENT | CREATE_DEFAULT_ERROR_MODE;
	BOOL wait = true;
	DWORD add_count = 0;
	PSID* add_groups = nullptr;
	unsigned __int64 priv_present = 0xFFFFFFFFE;
	DWORD session_id = -1, lsass_pid = get_lsass_pid();
	if (lsass_pid == -1) ExitProcess(0x102);

	for (int i = 1; i < argc; ++i)
	{
		if (!lstrcmpiW(argv[i], L"-acl"))
		{
			if (++i >= argc) ExitProcess(0x103);
			dacl = argv[i];
		}
		else if (!lstrcmpiW(argv[i], L"-d"))
		{
			if (++i >= argc) ExitProcess(0x103);
			startup_info.lpDesktop = argv[i];
		}
		else if (!lstrcmpiW(argv[i], L"-p"))
		{
			if (++i >= argc) ExitProcess(0x103);
			priv_present = wcstoui64_ntdll(argv[i], nullptr, 16);
		}
		else if (!lstrcmpiW(argv[i], L"-s"))
		{
			if (++i >= argc) ExitProcess(0x103);
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
			if (++i >= argc) ExitProcess(0x103);
			if (!lstrcmpiW(argv[i], L"UT")) mandatory.SubAuthority[0] = SECURITY_MANDATORY_UNTRUSTED_RID;
			else if (!lstrcmpiW(argv[i], L"LW")) mandatory.SubAuthority[0] = SECURITY_MANDATORY_LOW_RID;
			else if (!lstrcmpiW(argv[i], L"ME")) mandatory.SubAuthority[0] = SECURITY_MANDATORY_MEDIUM_RID;
			else if (!lstrcmpiW(argv[i], L"MP")) mandatory.SubAuthority[0] = SECURITY_MANDATORY_MEDIUM_PLUS_RID;
			else if (!lstrcmpiW(argv[i], L"HI")) mandatory.SubAuthority[0] = SECURITY_MANDATORY_HIGH_RID;
			else if (!lstrcmpiW(argv[i], L"SI")) mandatory.SubAuthority[0] = SECURITY_MANDATORY_SYSTEM_RID;
			else mandatory.SubAuthority[0] = wcstoul_ntdll(argv[i], nullptr, 10);
		}
		else if (!lstrcmpiW(argv[i], L"-g"))
		{
			if (++i >= argc || add_count) ExitProcess(0x103);
			add_count = wcstoul_ntdll(argv[i], nullptr, 10);
			add_groups = static_cast<PSID*>(LocalAlloc(LPTR, add_count * sizeof(PSID)));
			for (DWORD j = 0; j < add_count; j++)
			{
				if (++i >= argc) ExitProcess(0x103);
				if (!ConvertStringSidToSidW(argv[i], &add_groups[j])) ExitProcess(0x104);
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
	LocalFree(argv);
	PSID uid;
	if (!ConvertStringSidToSidW(user, &uid)) ExitProcess(0x105);

	auto token = INVALID_HANDLE_VALUE;
	if (!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &token)) ExitProcess(0x107);
	enable_all_privileges(token);
	if (session_id == -1) {
		DWORD length;
		GetTokenInformation(token, TokenSessionId, &session_id, sizeof(DWORD),
				&length);
		if (session_id == -1) ExitProcess(0x108);
	}
	LUID authid = get_auth_id(uid, session_id);
	PSID logon_sid = get_logon_sid(token);
	CloseHandle(token);

	auto dup_token = INVALID_HANDLE_VALUE;
	if (!get_token_pid(lsass_pid, &token)) ExitProcess(0x109);
	BOOL ret = DuplicateTokenEx(token, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation,
	                            TokenImpersonation, &dup_token);
	if (!ret) ExitProcess(0x110);
	CloseHandle(token);
	enable_all_privileges(dup_token);
	if (!SetThreadToken(nullptr, dup_token)) ExitProcess(0x111);
	CloseHandle(dup_token);

	token = create_token(uid, priv_present, logon_sid, authid, dacl, add_groups, add_count, &mandatory);
	if (!token) ExitProcess(0x112);
	LocalFree(uid);
	SetTokenInformation(token, TokenSessionId, static_cast<PVOID>(&session_id), sizeof(DWORD));

	PROCESS_INFORMATION process_info = {0};
	LPVOID lpEnvironment = nullptr;
	CreateEnvironmentBlock(&lpEnvironment, token, TRUE);
	LPWSTR working_directory = current_directory();
	LPWSTR cmdline = expand_environment(cmd);
	ret = CreateProcessAsUserW(token, NULL, cmdline, NULL, NULL, false, creation_flags, lpEnvironment,
	                           working_directory, &startup_info, &process_info);
	if (!ret) ExitProcess(0x113);

	CloseHandle(token);
	DestroyEnvironmentBlock(lpEnvironment);
	LocalFree(cmdline);
	LocalFree(working_directory);
	FreeConsole();
	DWORD exit_code = 0;
	if (wait) {
		WaitForSingleObjectEx(process_info.hProcess, INFINITE, false);
		GetExitCodeProcess(process_info.hProcess, &exit_code);
	}
	CloseHandle(process_info.hThread);
	CloseHandle(process_info.hProcess);
	ExitProcess(exit_code);
}
