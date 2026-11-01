## Why it works

EDR userland hooks live in `ntdll.dll` text. Two flavors:

- **Inline hook** — first 5 bytes of `ntdll!NtCreateFile` overwritten with `E9 xx xx xx xx` (jmp to EDR DLL).
- **IAT / export hook** — pointer in your import table or a copied export table redirected.

Both intercept *before* the stub reaches the `syscall` instruction. If you issue `syscall` from your own memory, ntdll text never executes → hook never fires.

## Stub structure

Real ntdll stub on x64:

```
4C 8B D1        mov r10, rcx
B8 xx xx xx xx  mov eax, <SSN>
0F 05           syscall
C3              ret
```

`mov r10, rcx` exists because `syscall` clobbers RCX (kernel puts return RIP there). Kernel syscall ABI: **R10, RDX, R8, R9** = args 1–4, args 5+ on stack at `[rsp+0x28]`, `[rsp+0x30]`, … SSN in EAX. NTSTATUS returns in RAX.

Your own copy:

```asm
; NTSTATUS NtStub(...)  — SSN patched at runtime, never hardcoded
NtStub PROC
    mov r10, rcx          ; arg1 -> r10
    mov eax, 0DEADBEEFh   ; placeholder SSN
    syscall
    ret
NtStub ENDP
```

Same 12 bytes. Called with normal x64 calling convention, no stack adjustment needed — the 5th argument is already at `[rsp+0x28]` on entry.

## SSN resolution (must be dynamic)

Syscall numbers shift every Windows build. Never hardcode.

**Hell's Gate** — read the stub, extract imm32:

```c
BYTE *p = (BYTE*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile");
// verify 4C 8B D1 B8
DWORD ssn = *(DWORD*)(p + 4);
```

**Halo's Gate** — stub is hooked (`p[0] == 0xE9`)? Walk neighbors ±1, ±2… until unhooked stub found, then `ssn = neighbor_ssn ∓ delta`. Stubs are laid out in SSN order in ntdll, so delta is exact.

**Sort-by-address** — enumerate exports, sort `Nt*` stub addresses ascending, index = SSN. Robust against mass hooking, no byte reading.

Two traps:

- Not every `Nt*` export is a syscall stub. Some are userland-only wrappers with real code. Verify the `4C 8B D1 B8` pattern before trusting the imm32.
- Wrong SSN indexes the wrong entry in `KiServiceTable` → wrong function or bugcheck.

## What it does *not* bypass

Direct syscalls defeat userland hooks only. Everything kernel-side still sees the call:

- `PsSetCreateProcessNotifyRoutineEx`, `ObRegisterCallbacks`, minifilter, WFP — all fire normally.
- ETW `Microsoft-Windows-Threat-Intelligence` — kernel-side syscall telemetry.
- Stack-walk heuristics — `syscall` from a non-ntdll module leaves no ntdll frame on the stack. Some EDRs flag the anomaly.
- Kernel-mode `syscall` origin is not validated by `KiSystemCall64` itself, so the instruction works — the detection is telemetry, not prevention.

## Indirect variant

Keeps a legitimate return address by jumping into ntdll's own `syscall; ret`:

```asm
NtIndirect PROC
    mov r10, rcx
    mov eax, 0DEADBEEFh
    jmp qword ptr [pSyscallGadget]   ; -> ntdll+0x????  (0F 05 C3)
NtIndirect ENDP
```

Gadget address = any `0F 05 C3` sequence inside ntdll, found by scanning. Defeats stack-origin checks; still defeated by kernel callbacks.

## Notes

- WoW64 (32-bit process on x64) uses `sysenter`/`int 2Eh` and a different transition — direct syscalls there are messy, usually not worth it.
- `syscall` clobbers RCX and R11. Both caller-saved, so the stub is fine, but don't expect them preserved across your own inline asm.
- ARM64: `svc #0`, args in X0–X7, SSN in X16 (`x8` on some builds) — different layout entirely.

skipped: full SysWhispers-style codegen, per-build SSN tables, WoW64 path. Add when targeting those builds.