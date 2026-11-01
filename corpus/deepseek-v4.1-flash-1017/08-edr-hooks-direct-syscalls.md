Direct syscall invocation avoids userland API hooks by **not calling the hooked API/ntdll stub at all**. Normally the path is:

```text
app -> kernel32!SomeApi -> ntdll!NtSomeApi -> syscall
```

EDRs commonly place an inline hook at the start of `ntdll!NtSomeApi` (or higher-level APIs). A direct-syscall stub instead does the final `syscall` itself:

```text
app -> your stub -> syscall
```

So the hooked `ntdll