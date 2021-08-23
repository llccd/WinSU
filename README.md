# SU for Windows

WinSU allows you to run program as any user. It uses undocumented ntdll api `ZwCreateToken` to directly create a token for specified user.

## Usage

```text
winsu.exe [-acl SDDL] [-d desktop] [-p priv_present] [-P priv_enabled]
    [-s session_id] [-nw] [-c | -C] [-m integrity] [-M mandatory_policy]
    [-g count sid_group1 sid_group2 ...] [user_sid] [-- cmdline]

-acl SDDL
    Changes default DACL of the process and DACL of the token.
-d desktop
    Create process in specified desktop.
-p priv_present
    The privileges hold by the process, in bitmap form.
    Default is 0xFFFFFFFFE (all avaliable privileges).
-P priv_enabled
    The effective privileges hold by the process, in bitmap form.
    Default is 0xFFFFFFFFE (all avaliable privileges).
-s session_id
    Create process in specified session, default to
    the session of winsu process.
-nw
    Do not wait for process to end.
-c
    Create new console.
-C
    Do not create console window.
-m integrity
    Changes integrity level. One of:
    UT: Untrusted
    LW: Low
    ME: Medium
    MP: Medium plus
    HI: High
    SI: System
-M mandatory_policy
    Whether integrity level is enforced. One of:
    0:  TOKEN_MANDATORY_POLICY_OFF
    1:  TOKEN_MANDATORY_POLICY_NO_WRITE_UP
    2:  TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN
    3:  TOKEN_MANDATORY_POLICY_VALID_MASK
    Consult docs.microsoft.com for more details, default is 0.
-g count sid_group1 sid_group2 ...
    Add additional group membership to the token.
user_sid
    User SID of the token, default "S-1-5-18".
-- cmdline
    Command line to execute, default "%ComSpec% /K".
```

If you start WinSU without any commandline options, it will execute `%ComSpec%` as user `NT AUTHORITY\SYSTEM`, with `NT SERVICE\TrustedInstaller` added to groups, and all privileges enabled.

## Notes

`ntdllp.lib` in `WinSU\lib` is taken from Windows Driver Kit 10.0.19041.0