# SeImpersonatePrivilege token impersonation

**Sequence:**

1. Process with `SeImpersonatePrivilege` enabled calls `LogonUser` (or a variant) to get a logon session token for a target account — needs creds, or a service account that can authenticate.
2. Or: obtains token from a process it can open — `OpenProcess` → `OpenProcessToken` with `TOKEN_DUPLICATE`. Requires `PROCESS_QUERY_INFORMATION` on target.
3. `DuplicateTokenEx` — duplicate to `SecurityImpersonation` level, `TokenImpersonation` type.
4. `ImpersonateLoggedOnUser` (or `SetThreadToken`) — thread now runs as that token.
5. While impersonating: access resources the token's SIDs grant. `RevertToSelf` to drop back.

**Why it's a privesc:** service accounts (IIS `IIS_IUSRS`/`NT AUTHORITY\NETWORK SERVICE`, MSSQL `NT SERVICE\MSSQLSERVER`, etc.) hold this by default. If you land code in such a process, you can impersonate any token you can reach — including `SYSTEM` or `Administrator` tokens from processes running as those accounts — then spawn a process as them.

**Tool + command (Potato family — the classic abuse):**

```
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami" -t *
```

- `-l 1337` — COM listener port
- `-p` — program to run
- `-a` — args
- `-t *` — try all token types

Other variants for different Windows builds: `RoguePotato`, `SweetPotato`, `PrintSpoofer` (`PrintSpoofer.exe -i -c cmd`), `GodPotato` (`GodPotato.exe -cmd "cmd /c whoami"`).

**Mitigation:** remove `SeImpersonatePrivilege` from service accounts that don't need it; run services as virtual accounts with restricted tokens; enable `SeImpersonatePrivilege` audit; patch for the specific COM/print-spooler abuse vector (Potato family relies on unpatched COM activation or the Print Spooler RPC).

Skipped: full C++ PoC — add when you need to reproduce without a prebuilt binary.