#include <windows.h>
#include <psapi.h>
#include <winternl.h>
#include <sddl.h>
#include <userenv.h>
#define _NTDEF_
#include <ntsecapi.h>

#ifdef _DEBUG
#include <iostream>
#define EXIT(msg, x) {puts(msg); return x;}
#define EXIT1(x) {return x;}
#else
#define EXIT(msg, x) {ExitProcess(x);}
#define EXIT1(x) {ExitProcess(x);}
#endif

extern "C" NTSTATUS NTAPI ZwCreateToken(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN TOKEN_TYPE Type,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PSID* Owner,
	IN PSID* PrimaryGroup,
	IN PACL* DefaultDacl,
	IN PTOKEN_SOURCE Source
);

template <size_t N>
struct SIDN
{
	UCHAR Revision;
	UCHAR SubAuthorityCount;
	SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
	ULONG SubAuthority[N];
};

static SID Everyone = { 1, 1, {SECURITY_WORLD_SID_AUTHORITY}, {SECURITY_WORLD_RID} };
static SID Local = { 1, 1, {SECURITY_LOCAL_SID_AUTHORITY}, {SECURITY_LOCAL_RID} };
static SID ConsoleLogon = { 1, 1, {SECURITY_LOCAL_SID_AUTHORITY}, {SECURITY_LOCAL_LOGON_RID} };
static SID INTERACTIVE = { 1, 1, {SECURITY_NT_AUTHORITY}, {SECURITY_INTERACTIVE_RID} };
static SID AuthenticatedUsers = { 1, 1, {SECURITY_NT_AUTHORITY}, {SECURITY_AUTHENTICATED_USER_RID} };
static SID ThisOrganization = { 1, 1, {SECURITY_NT_AUTHORITY}, {SECURITY_THIS_ORGANIZATION_RID} };
static SID LocalSystem = { 1, 1, {SECURITY_NT_AUTHORITY}, {SECURITY_LOCAL_SYSTEM_RID} };
static SID LocalAccount = { 1, 1, {SECURITY_NT_AUTHORITY}, {SECURITY_LOCAL_ACCOUNT_RID} };
static SID LocalAccountAndAdmin = { 1, 1, {SECURITY_NT_AUTHORITY}, {SECURITY_LOCAL_ACCOUNT_AND_ADMIN_RID} };
static SID mandatory = { 1, 1, {SECURITY_MANDATORY_LABEL_AUTHORITY}, {SECURITY_MANDATORY_SYSTEM_RID} };
static SIDN<2> Administrators = { 1, 2, {SECURITY_NT_AUTHORITY}, {SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS} };
static SIDN<2> Users = { 1, 2, {SECURITY_NT_AUTHORITY}, {SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_USERS} };
static SIDN<6> TrustedInstaller = { 1, 6, {SECURITY_NT_AUTHORITY}, {80,956008885,3418522649,1831038044,1853292631,2271478464} };

static HANDLE heap = 0;

DWORD count_one(DWORD64 x)
{
	x = (x & 0x5555555555555555) + (x >> 1 & 0x5555555555555555);
	x = (x & 0x3333333333333333) + (x >> 2 & 0x3333333333333333);
	x = (x & 0x0f0f0f0f0f0f0f0f) + (x >> 4 & 0x0f0f0f0f0f0f0f0f);
	x = (x & 0x00ff00ff00ff00ff) + (x >> 8 & 0x00ff00ff00ff00ff);
	x = (x & 0x0000ffff0000ffff) + (x >> 16 & 0x0000ffff0000ffff);
	x = (x & 0x00000000ffffffff) + (x >> 32 & 0x00000000ffffffff);
	return (DWORD)x;
}

PTOKEN_PRIVILEGES generate_privilege(const DWORD64& priv, const DWORD64& enabled)
{
	const auto priv_count = count_one(priv);
	auto privileges = (PTOKEN_PRIVILEGES)HeapAlloc(heap, 0, FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges[priv_count]));
	if (!privileges) return NULL;

	privileges->PrivilegeCount = priv_count;

	for (DWORD i = 0, j = 0; i < 64; ++i)
	{
		if (priv & (DWORD64)1 << i)
		{
			if (enabled & (DWORD64)1 << i)
				privileges->Privileges[j].Attributes = SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;
			privileges->Privileges[j++].Luid.LowPart = i + 1;

			if (j >= priv_count) break;
		}
	}

	return privileges;
}

PTOKEN_GROUPS generate_groups(const PSID& logon_sid, PSID* add_groups, const DWORD& add_count, const PSID& integrity)
{
	DWORD group_count = 12 + add_count;
	if (logon_sid) group_count++;

	auto groups = (PTOKEN_GROUPS)HeapAlloc(heap, 0, FIELD_OFFSET(TOKEN_GROUPS, Groups[group_count]));
	if (!groups) return NULL;

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
	groups->Groups[9].Sid = (PSID)&Users;
	groups->Groups[9].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY;
	groups->Groups[10].Sid = (PSID)&Administrators;
	groups->Groups[10].Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_MANDATORY |
		SE_GROUP_OWNER;

	groups->Groups[11].Sid = (PSID)&TrustedInstaller;
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
	for (DWORD i = 12; i < groups->GroupCount; ++i) HeapFree(heap, 0, groups->Groups[i].Sid);
	HeapFree(heap, 0, groups);
}

LPVOID get_token_info(HANDLE token, const TOKEN_INFORMATION_CLASS& type)
{
	DWORD length;
	void* buf = NULL;
	GetTokenInformation(token, type, NULL, 0, &length);
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		buf = (void*)HeapAlloc(heap, 0, length);
		if (!buf) return NULL;
		GetTokenInformation(token, type, buf, length, &length);
	}
	return buf;
}

void enable_all_privileges(HANDLE token)
{
	auto privileges = (PTOKEN_PRIVILEGES)get_token_info(token, TokenPrivileges);
	if (privileges)
	{
		for (DWORD i = 0; i < privileges->PrivilegeCount; ++i)
			privileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;

		AdjustTokenPrivileges(token, false, privileges, 0, NULL, NULL);
		HeapFree(heap, 0, privileges);
	}
}

PSID get_logon_sid(HANDLE token)
{
	PSID logon_sid = NULL;
	auto groups = (PTOKEN_GROUPS)get_token_info(token, TokenGroups);
	if (!groups) return NULL;

	for (DWORD i = 0; i < groups->GroupCount; ++i)
		if (groups->Groups[i].Attributes & SE_GROUP_LOGON_ID)
		{
			const auto length = GetLengthSid(groups->Groups[i].Sid);
			logon_sid = (PSID)HeapAlloc(heap, 0, length);
			if (!logon_sid) break;

			if (!CopySid(length, logon_sid, groups->Groups[i].Sid))
			{
				HeapFree(heap, 0, logon_sid);
				logon_sid = NULL;
			}
			break;
		}

	HeapFree(heap, 0, groups);
	return logon_sid;
}

LUID get_auth_id(const PSID& uid, const DWORD& session_id)
{
	ULONG session_count;
	PLUID session_list;
	LUID auth_id = SYSTEM_LUID;
	if (LsaEnumerateLogonSessions(&session_count, &session_list)) return auth_id;

	for (ULONG i = 0; i < session_count; ++i)
	{
		PSECURITY_LOGON_SESSION_DATA session_data;
		if (LsaGetLogonSessionData(&session_list[i], &session_data)) break;
		if (session_data->Sid && EqualSid(session_data->Sid, uid))
		{
			auth_id = session_data->LogonId;
			if (session_id == session_data->Session)
			{
				LsaFreeReturnBuffer(session_data);
				break;
			}
		}
		LsaFreeReturnBuffer(session_data);
	}

	LsaFreeReturnBuffer(session_list);
	return auth_id;
}

BOOL get_token_pid(const DWORD& ProcessId, PHANDLE TokenHandle)
{
	auto process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
	if (GetLastError() == ERROR_ACCESS_DENIED) process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ProcessId);
	if (!process) return false;

	const auto ret = OpenProcessToken(process, MAXIMUM_ALLOWED, TokenHandle);

	CloseHandle(process);
	return ret;
}

DWORD get_lsass_pid()
{
	const auto scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (!scm) return -1;

	const auto service = OpenServiceW(scm, L"SamSs", SERVICE_QUERY_STATUS);
	if (!service)
	{
		CloseServiceHandle(scm);
		return -1;
	}
	
	SERVICE_STATUS_PROCESS status;
	DWORD bytes_needed = sizeof(status);
	DWORD pid = -1;
	if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &bytes_needed))
		if (SERVICE_STOPPED != status.dwCurrentState) pid = status.dwProcessId;
	
	CloseServiceHandle(service);
	CloseServiceHandle(scm);
	return pid;
}

HANDLE create_token(const PSID& uid, const DWORD64& priv_present, const DWORD64& priv_enabled,
	const PSID& logon_sid, LUID authid, LPCWSTR dacl, PSID* add_groups, DWORD add_count, const PSID& mandatory)
{
	SECURITY_QUALITY_OF_SERVICE sqos = {sizeof(sqos), SecurityDelegation, SECURITY_STATIC_TRACKING, FALSE};
	OBJECT_ATTRIBUTES oa = {sizeof(oa), NULL, NULL, 0, NULL, &sqos};
	LARGE_INTEGER li = { {0xFFFFFFFF, -1} };
	TOKEN_SOURCE source = { {'F', 'r', 'e', 'e', 'H', 'K', 0}, {0x99996E2F, 0x51495FA9} };

	PSECURITY_DESCRIPTOR sd;
	if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(dacl, SDDL_REVISION_1, &sd, NULL))
		return NULL;

	PSID owner;
	PSID primary_group;
	PACL default_dacl;
	BOOL present = false, defaulted = false;
	GetSecurityDescriptorOwner(sd, &owner, &defaulted);
	if (!owner) owner = uid;
	GetSecurityDescriptorGroup(sd, &primary_group, &defaulted);
	if (!primary_group) primary_group = (PSID)&Administrators;
	GetSecurityDescriptorDacl(sd, &present, &default_dacl, &defaulted);
	
	if (!present) {
		DWORD size = sizeof(ACL) + (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + sizeof(LocalSystem);
		size += (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + sizeof(Administrators);
		if (logon_sid) size += (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + GetLengthSid(logon_sid);
		size = (size + (sizeof(DWORD) - 1)) & 0xfffffffc;
		default_dacl = (PACL)HeapAlloc(heap, 0, size);
		if (!default_dacl)
		{
			HeapFree(heap, 0, sd);
			return NULL;
		}

		InitializeAcl(default_dacl, size, ACL_REVISION);
		AddAccessAllowedAce(default_dacl, ACL_REVISION, GENERIC_ALL, &LocalSystem);
		AddAccessAllowedAce(default_dacl, ACL_REVISION, GENERIC_ALL, (PSID)&Administrators);
		if (logon_sid)
			AddAccessAllowedAce(default_dacl, ACL_REVISION, GENERIC_READ | GENERIC_EXECUTE, logon_sid);
	}

	TOKEN_USER user = { {uid, 0} };
	auto groups = generate_groups(logon_sid, add_groups, add_count, mandatory);
	auto privileges = generate_privilege(priv_present, priv_enabled);

	HANDLE elevated_token = NULL;
	ZwCreateToken(&elevated_token, TOKEN_ALL_ACCESS, &oa, TokenPrimary, &authid, &li, &user, groups, privileges,
	              &owner, &primary_group, &default_dacl, &source);

	if (!present) HeapFree(heap, 0, default_dacl);
	LocalFree(sd);
	HeapFree(heap, 0, privileges);
	free_groups(groups);
	return elevated_token;
}

LPWSTR expand_environment(LPCWSTR src)
{
	const auto char_count = ExpandEnvironmentStringsW(src, NULL, 0);
	if (!char_count) return NULL;

	const auto dst = (LPWSTR)HeapAlloc(heap, 0, char_count * sizeof(WCHAR));
	if (!dst) return NULL;

	if (char_count == ExpandEnvironmentStringsW(src, dst, char_count)) return dst;

	HeapFree(heap, 0, dst);
	return NULL;
}

LPWSTR current_directory()
{
	const auto char_count = GetCurrentDirectoryW(0, NULL);
	if (!char_count) return NULL;

	const auto dst = (LPWSTR)HeapAlloc(heap, 0, char_count * sizeof(WCHAR));
	if (!dst) return NULL;

	if (char_count == GetCurrentDirectoryW(char_count, dst) + 1) return dst;

	HeapFree(heap, 0, dst);
	return NULL;
}

int main()
{
	heap = GetProcessHeap();
	if (!heap) EXIT("GetProcessHeap() Failed", 0x100);
	
	int argc;
	const auto current_cmdline = GetCommandLineW();
	const auto argv = CommandLineToArgvW(current_cmdline, &argc);
	if (!argv) EXIT("CommandLineToArgv() Failed", 0x101);

	PSID user = &LocalSystem;
	auto cmd = L"%ComSpec% /K";
	auto dacl = L"G:BA";
	STARTUPINFOW startup_info;
	startup_info.cb = sizeof(STARTUPINFOW);
	startup_info.cbReserved2 = 0;
	startup_info.lpDesktop = NULL;
	startup_info.lpTitle = NULL;
	startup_info.lpReserved = NULL;
	startup_info.lpReserved2 = NULL;
	startup_info.dwFlags = 0;
	DWORD creation_flags = CREATE_UNICODE_ENVIRONMENT | CREATE_DEFAULT_ERROR_MODE;
	BOOL wait = true;
	DWORD add_count = 0;
	PSID* add_groups = NULL;
	DWORD64 priv_present = 0xFFFFFFFFE, priv_enabled = 0xFFFFFFFFE;
	TOKEN_MANDATORY_POLICY mandatory_policy = { 0 };
	DWORD session_id = -1;

	for (int i = 1; i < argc; ++i)
	{
		if (!lstrcmpiW(argv[i], L"-acl"))
		{
			if (++i >= argc) EXIT("Insufficient argument", 0x103);
			dacl = argv[i];
		}
		else if (!lstrcmpiW(argv[i], L"-d"))
		{
			if (++i >= argc) EXIT("Insufficient argument", 0x103);
			startup_info.lpDesktop = argv[i];
		}
		else if (!lstrcmpiW(argv[i], L"-p"))
		{
			if (++i >= argc) EXIT("Insufficient argument", 0x103);
			if (*(argv[i - 1] + 1) == L'P') priv_enabled = _wcstoui64(argv[i], NULL, 16);
			else priv_present = _wcstoui64(argv[i], NULL, 16);
		}
		else if (!lstrcmpiW(argv[i], L"-s"))
		{
			if (++i >= argc) EXIT("Insufficient argument", 0x103);
			if (*(argv[i - 1] + 1) == L'S')
			{
				startup_info.wShowWindow = (WORD)wcstoul(argv[i], NULL, 10);
				startup_info.dwFlags |= STARTF_USESHOWWINDOW;
			}
			else session_id = wcstoul(argv[i], NULL, 16);
		}
		else if (!lstrcmpiW(argv[i], L"-nw"))
		{
			wait = false;
		}
		else if (!lstrcmpiW(argv[i], L"-c"))
		{
			if (*(argv[i] + 1) == L'C') creation_flags |= CREATE_NO_WINDOW;
			else creation_flags |= CREATE_NEW_CONSOLE;
		}
		else if (!lstrcmpiW(argv[i], L"-m"))
		{
			if (++i >= argc) EXIT("Insufficient argument", 0x103);
			if (*(argv[i - 1] + 1) == L'M') mandatory_policy.Policy = wcstoul(argv[i], NULL, 10);
			else switch (*argv[i]) {
			case L'U':
			case L'u':
				mandatory.SubAuthority[0] = SECURITY_MANDATORY_UNTRUSTED_RID;
				break;
			case L'L':
			case L'l':
				mandatory.SubAuthority[0] = SECURITY_MANDATORY_LOW_RID;
				break;
			case L'M':
			case L'm':
				if (*(argv[i] + 1) == L'P' || *(argv[i] + 1) == L'p')
					mandatory.SubAuthority[0] = SECURITY_MANDATORY_MEDIUM_PLUS_RID;
				else
					mandatory.SubAuthority[0] = SECURITY_MANDATORY_MEDIUM_RID;
				break;
			case L'H':
			case L'h':
				mandatory.SubAuthority[0] = SECURITY_MANDATORY_HIGH_RID;
				break;
			case L'S':
			case L's':
				mandatory.SubAuthority[0] = SECURITY_MANDATORY_SYSTEM_RID;
				break;
			default:
				mandatory.SubAuthority[0] = wcstoul(argv[i], NULL, 10);
			}
		}
		else if (!lstrcmpiW(argv[i], L"-g"))
		{
			if (++i >= argc) EXIT("Insufficient argument", 0x103);
			if (add_count) HeapFree(heap, 0, add_groups);
			add_count = wcstoul(argv[i], NULL, 10);
			add_groups = (PSID*)HeapAlloc(heap, 0, add_count * sizeof(PSID));
			if (!add_groups) EXIT("HeapAlloc() failed", 0x103);
			for (DWORD j = 0; j < add_count; j++)
			{
				if (++i >= argc) EXIT("Insufficient argument", 0x103);
				if (!ConvertStringSidToSidW(argv[i], &add_groups[j])) EXIT("ConvertStringSidToSid() failed", 0x104);
			}
		}
		else if (!lstrcmpiW(argv[i], L"--"))
		{
			if (++i >= argc) break;
			cmd = wcsstr(current_cmdline, L"--") + 2;
			while (cmd && *cmd == L' ') cmd++;
			break;
		}
		else {
			if (!ConvertStringSidToSidW(argv[i], &user)) EXIT("ConvertStringSidToSid() failed", 0x105);
		}
	}

	if (session_id == -1)
	{
		ProcessIdToSessionId(GetCurrentProcessId(), &session_id);
		if (session_id == -1) session_id = 0;
	}

	HANDLE token;
	if (!OpenProcessToken(GetCurrentProcess(), MAXIMUM_ALLOWED, &token)) EXIT("Open token of CurrentProcess failed", 0x107);
	enable_all_privileges(token);
	auto authid = get_auth_id(user, session_id);
	auto logon_sid = get_logon_sid(token);
	CloseHandle(token);

	if (!get_token_pid(get_lsass_pid(), &token)) EXIT("Open token of lsass.exe failed", 0x109);
	HANDLE dup_token;
	if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &dup_token)) EXIT("Duplicate impersonation token of lsass.exe failed", 0x110);
	CloseHandle(token);
	enable_all_privileges(dup_token);
	if (!(SetThreadToken(NULL, dup_token) || ImpersonateLoggedOnUser(dup_token))) EXIT("Impersonate SYSTEM failed", 0x111);
	CloseHandle(dup_token);

	token = create_token(user, priv_present, priv_enabled, logon_sid, authid, dacl, add_groups, add_count, &mandatory);
	if (!token) EXIT("Failed to create token", 0x112);
	if (user != &LocalSystem) LocalFree(user);

	SetTokenInformation(token, TokenMandatoryPolicy, (void*)&mandatory_policy, sizeof(TOKEN_MANDATORY_POLICY));
	SetTokenInformation(token, TokenSessionId, (void*)&session_id, sizeof(DWORD));

	PROCESS_INFORMATION process_info;
	void* lpEnvironment = NULL;
	CreateEnvironmentBlock(&lpEnvironment, token, TRUE);
	auto working_directory = current_directory();
	auto cmdline = expand_environment(cmd);
	LocalFree(argv);
	if (!CreateProcessAsUserW(token, NULL, cmdline, NULL, NULL, false, creation_flags, lpEnvironment,
	                           working_directory, &startup_info, &process_info))
		EXIT("CreateProcessAsUser() failed", 0x113);

	CloseHandle(token);
	DestroyEnvironmentBlock(lpEnvironment);
	HeapFree(heap, 0, cmdline);
	HeapFree(heap, 0, working_directory);
	FreeConsole();
	CloseHandle(process_info.hThread);
	DWORD exit_code = 0;
	if (wait)
	{
		WaitForSingleObjectEx(process_info.hProcess, INFINITE, false);
		GetExitCodeProcess(process_info.hProcess, &exit_code);
	}
	EXIT1(exit_code);
}
