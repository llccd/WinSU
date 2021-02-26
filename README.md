# SU for Windows

WinSU allows you to run program as any user. It uses undocumented ntdll api `ZwCreateToken` to directly create a token for specified user.

## Usage

If you start WinSU without any commandline options, it will execute `%SYSTEMROOT%\System32\cmd.exe` as user `NT AUTHORITY\SYSTEM`, with `NT SERVICE\TrustedInstaller` added to groups, and all privileges enabled.

## Compile

with C runtime

```shell
cl winsu.cpp /GS- /Gy /GL /O2 /link /OPT:REF
```

without C runtime (smaller binary size)

```shell
cl winsu.cpp /GS- /Gy /GL /O2 /link /ENTRY:main /OPT:REF
```
