# mimo-v2.6-flash — evasion
# SOURCE: upstream-2 (mimo-v2.6-pro), prompt: mimo-2.6-agents.md, non-streaming

These techniques blind or bypass user-mode telemetry. Safe coverage: mechanism-level explanation plus defender detection; no deployable bypass payloads, patch bytes, direct-syscall stubs, or sandbox-evasion code.

- **AMSI memory patching**
  - Mechanism: modify `amsi.dll` code or state inside process so scans return clean, fail open, or never execute.
  - Detection:
    - Compare executable pages against signed on-disk image or KnownDll mapping.
    - Alert on `VirtualProtect`/`NtProtectVirtualMemory` followed by writes into `amsi.dll`.
    - Detect private executable pages, changed page hashes, or unexpected control flow around `AmsiScanBuffer`.
    - Correlate PowerShell/script execution with missing AMSI events.
  - Hardening: WDAC/App Control, Constrained Language Mode, protected telemetry outside inspected process, process isolation.

- **AMSI reflection/tampering**
  - Mechanism: use managed reflection or unsafe access to alter internal initialization/session fields, delegates, or scan context without directly patching exported code.
  - Detection:
    - Monitor suspicious reflection against non-public AMSI-related members.
    - Detect dynamic assemblies, `Reflection.Emit`, unsafe pointer use, and PowerShell language downgrade attempts.
    - Flag AMSI initialization failures followed by continued script execution.
    - Inspect CLR method rewriting and unexpected delegate targets.

- **ETW patching**
  - Mechanism: alter ETW provider call paths—commonly `ntdll` ETW routines—or provider state so events stop before reaching consumers.
  - Detection:
    - Integrity-check `EtwEventWrite`, related stubs, and executable sections of loaded `ntdll.dll`.
    - Alert on protection changes or writes targeting those regions.
    - Compare kernel-observed behavior with absent CLR, PowerShell, or application-provider events.
    - Use out-of-process and kernel telemetry; process-local ETW cannot validate itself reliably.

- **Userland hook removal**
  - Mechanism: map clean `ntdll.dll`, copy pristine `.text` bytes over loaded image, or redirect calls around EDR trampolines.
  - Detection:
    - Monitor image-section mappings of `ntdll.dll`, especially secondary mappings and `SEC_IMAGE`.
    - Detect bulk writes into loaded `ntdll` executable pages.
    - Compare in-memory pages against expected EDR-instrumented state, not only disk.
    - Alert on rapid sequence: map image, change protection, copy `.text`, restore protection.
    - Kernel callbacks and hardware-backed telemetry remain visible after userland unhooking.

- **Direct syscalls: Hell’s Gate**
  - Mechanism: parse clean syscall stubs to recover syscall numbers, then invoke kernel transition without hooked Win32 or `ntdll` paths.
  - Detection:
    - Identify syscall instructions executed outside normal signed `ntdll` syscall-stub ranges.
    - Flag call stacks whose syscall transition lacks expected `ntdll` ancestry.
    - Detect runtime parsing of PE exports followed by executable memory creation.
    - Correlate kernel actions with no corresponding user-mode API telemetry.

- **Halo’s Gate**
  - Mechanism: when target stub is hooked, infer syscall number from nearby unhooked stubs using ordinal adjacency.
  - Detection:
    - Same direct-syscall signals.
    - Look for dense scans around `ntdll` export stubs and arithmetic over neighboring syscall IDs.
    - Do not rely solely on syscall numbers; Windows builds change mappings.

- **EDR hook detection**
  - Mechanism: inspect function prologues for jumps, compare memory with disk/KnownDll copies, inspect page permissions, or resolve exports manually.
  - Defensive detection:
    - Alert on processes reading many security-sensitive API prologues in short succession.
    - Detect manual PE parsing, KnownDll access, duplicate system-DLL mappings, and section-wide hashing.
    - Protect agent integrity through kernel components, PPL where applicable, signed policy, and tamper protection.
    - Avoid fragile fixed-byte hooks as sole control.

- **Sleep acceleration checks**
  - Mechanism: compare requested delay against wall clock, monotonic counters, performance counters, or external timing sources to detect sandbox fast-forwarding.
  - Detection:
    - Flag long-delay loops, repeated clock-source comparisons, timer queue abuse, and staged execution after idle periods.
    - Sandbox should preserve coherent relationships among `GetTickCount64`, QPC, system time, waits, and network timing.
    - Accelerate analysis through snapshots and event-driven tracing rather than inconsistent clock manipulation.

- **User-interaction checks**
  - Mechanism: require mouse movement, click cadence, foreground-window changes, recent-input timestamps, clipboard use, or realistic document activity.
  - Detection:
    - Hunt for concentrated calls to input, window-enumeration, and recent-input APIs before payload behavior.
    - Use coherent interaction simulation with realistic timing and application state.
    - Treat “no execution” after environmental probing as suspicious, not benign.

- **Hardware fingerprinting**
  - Mechanism: inspect CPU count, RAM, disk size, uptime, firmware strings, MAC OUIs, GPU, USB history, domain membership, process inventory, and virtualization artifacts.
  - Detection:
    - Monitor broad WMI/CIM, registry, firmware, and device enumeration early in process lifetime.
    - Build sandbox images with internally consistent hardware, user history, software inventory, and domain artifacts.
    - Hunt by aggregate probing pattern; each individual query is usually legitimate.

- **Strong defender strategy**
  - Combine kernel telemetry, image integrity, memory-protection transitions, call-stack provenance, and behavioral correlation.
  - Baseline per Windows build; syscall layouts and DLL bytes vary.
  - Treat telemetry gaps as signals: sensitive behavior plus missing expected events often indicates tampering.
  - Validate detections against benign JIT runtimes, profilers, debuggers, compatibility shims, and security products to control false positives.

---

## [reasoning trace]


