# mimo-v2.6-flash — ad-acl-deleg
# SOURCE: OAO gateway (mimo-v2.6-pro), prompt: mimo-2.6-agents.md, non-streaming

Queries below target BloodHound CE/OpenGraph-style labels and common AD edge names. Confirm property names against imported collector version; CE models ACL and delegation relationships as traversable edges, including `GenericAll`, `GenericWrite`, `WriteDacl`, `ForceChangePassword`, `AllowedToDelegate`, and `AllowedToAct`. [1][3]

## BloodHound discovery

```cypher
// Direct dangerous ACL edges
MATCH p=(a)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|
                     ForceChangePassword|AllExtendedRights]->(b)
RETURN p
LIMIT 1000
```

```cypher
// Paths from controlled principals to Tier Zero
MATCH (src)
WHERE src.owned = true
MATCH (dst)
WHERE dst.highvalue = true
MATCH p=shortestPath(
  (src)-[:MemberOf|GenericAll|GenericWrite|WriteDacl|WriteOwner|
          ForceChangePassword|AllExtendedRights|AddMember|
          AddSelf|AdminTo|AllowedToDelegate|AllowedToAct*1..]->(dst)
)
RETURN p
LIMIT 100
```

```cypher
// ACL control over users
MATCH p=(a)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|
                     ForceChangePassword|AllExtendedRights]->(u:User)
RETURN p
LIMIT 1000
```

```cypher
// ACL control over groups
MATCH p=(a)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|
                     AddMember|AddSelf]->(g:Group)
RETURN p
LIMIT 1000
```

```cypher
// ACL control over computers
MATCH p=(a)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner]->(c:Computer)
RETURN p
LIMIT 1000
```

```cypher
// Unconstrained delegation, excluding DCs
MATCH (c:Computer)
WHERE c.unconstraineddelegation = true
  AND coalesce(c.isdc, false) = false
RETURN c.name, c.enabled, c.operatingsystem
ORDER BY c.name
```

```cypher
// Constrained delegation
MATCH p=(a)-[:AllowedToDelegate]->(c:Computer)
RETURN p
LIMIT 1000
```

```cypher
// Constrained delegation with protocol transition
MATCH p=(a {trustedtoauth:true})-[:AllowedToDelegate]->(c:Computer)
RETURN p
LIMIT 1000
```

```cypher
// RBCD
MATCH p=(a)-[:AllowedToAct]->(c:Computer)
RETURN p
LIMIT 1000
```

```cypher
// Controlled principal reaching delegation opportunity
MATCH (src)
WHERE src.owned = true
MATCH p=(src)-[:MemberOf|GenericAll|GenericWrite|WriteDacl|
                      WriteOwner|AddMember|AllowedToAct|
                      AllowedToDelegate*1..]->(target)
RETURN p
LIMIT 1000
```

`AllowedToDelegate` represents constrained delegation; `AllowedToAct` represents RBCD in common BloodHound CE query sets. [3]

## GenericAll / GenericWrite / WriteDACL / password-reset validation

Exact takeover commands that modify passwords, SPNs, delegation, or DACLs omitted. Use disposable principals and snapshot-backed lab objects.

Read-only PowerView validation:

```powershell
Import-Module .\PowerView.ps1

$Target = "victim"
$Actor  = "LAB\operator"

Get-DomainObjectAcl -Identity $Target -ResolveGUIDs |
  Where-Object {
    $_.IdentityReference -eq $Actor -or
    $_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner|ExtendedRight"
  } |
  Format-List ObjectDN,IdentityReference,ActiveDirectoryRights,ObjectAceType,AceType,IsInherited
```

Native read-only checks:

```powershell
dsacls "CN=victim,OU=Users,DC=lab,DC=local"
```

```powershell
Get-ADUser victim -Properties servicePrincipalName,memberOf,userAccountControl |
  Format-List DistinguishedName,servicePrincipalName,memberOf,userAccountControl
```

Linux ACL inspection:

```bash
impacket-dacledit \
  -action read \
  -principal 'operator' \
  -target 'victim' \
  'LAB.LOCAL/operator:Password' \
  -dc-ip 10.0.0.10
```

StandIn inspection:

```powershell
.\StandIn_v13_Net45.exe --object victim --filter samaccountname
```

## Delegation discovery

```powershell
# Unconstrained delegation
Get-ADComputer -LDAPFilter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' `
  -Properties DNSHostName,userAccountControl |
  Select-Object Name,DNSHostName,userAccountControl

# Constrained delegation
Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' `
  -Properties sAMAccountName,msDS-AllowedToDelegateTo,userAccountControl |
  Select-Object sAMAccountName,msDS-AllowedToDelegateTo,userAccountControl

# RBCD
Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' `
  -Properties DNSHostName,msDS-AllowedToActOnBehalfOfOtherIdentity |
  Select-Object Name,DNSHostName,msDS-AllowedToActOnBehalfOfOtherIdentity
```

PowerView equivalents:

```powershell
Get-DomainComputer -Unconstrained |
  Select-Object samaccountname,dnshostname,useraccountcontrol

Get-DomainUser -TrustedToAuth |
  Select-Object samaccountname,msds-allowedtodelegateto

Get-DomainComputer -TrustedToAuth |
  Select-Object samaccountname,msds-allowedtodelegateto
```

## Defender artifacts

### ACL and account-object abuse

- `4724`: password-reset attempt.
- `4738`: user account changed.
- `4728`, `4732`, `4756`: member added to global, local, or universal security group.
- `5136`: directory object modified. Inspect `ObjectDN`, `AttributeLDAPDisplayName`, and changed value.
- `4662`: directory-object operation when matching SACL exists.
- `4670`: permissions on object changed.
- LDAP attributes worth alerting:
  - `nTSecurityDescriptor`
  - `servicePrincipalName`
  - `member`
  - `unicodePwd`
  - `userAccountControl`
  - `msDS-AllowedToDelegateTo`
  - `msDS-AllowedToActOnBehalfOfOtherIdentity`

Correlate `5136` changes with actor logon session, source workstation, object GUID, and follow-on Kerberos activity. Normal administrative tools can produce same events.

### SPN-based GenericWrite abuse

- `5136` showing `servicePrincipalName` added, changed, then removed.
- `4769` service-ticket request shortly after SPN modification.
- RC4 ticket encryption where domain normally uses AES.
- Unusual SPN placed on user account.
- Fast SPN add, TGS request, SPN removal sequence.

### Unconstrained delegation

- Computer has `TRUSTED_FOR_DELEGATION` (`0x80000`) in `userAccountControl`.
- Privileged interactive or network authentication reaches non-DC delegated host.
- `4624` privileged logon on delegated host.
- `4768` and `4769` activity tied to that host.
- LSASS access telemetry:
  - Sysmon `10`
  - EDR process-access event
  - unsigned or unusual process opening `lsass.exe`
- Unexpected TGT-bearing sessions or ticket-cache enumeration.

### Constrained delegation and S4U

- `4769` bursts where service account requests tickets for users who never logged on to source host.
- `4769` client/service combinations inconsistent with normal application flow.
- Changes to `msDS-AllowedToDelegateTo` through `5136`.
- `TRUSTED_TO_AUTH_FOR_DELEGATION` (`0x1000000`) added to `userAccountControl`.
- Rubeus execution indicators:
  - Image, command-line, module-load, AMSI, or EDR detections.
  - Base64 ticket material in command lines or process memory.
  - `.kirbi` file creation.
  - Kerberos ticket injection into unrelated logon sessions.

### RBCD

- `5136` modifying `msDS-AllowedToActOnBehalfOfOtherIdentity`.
- New computer account followed by RBCD change:
  - `4741`: computer account created.
  - `4742`: computer account changed.
  - `5136`: target computer delegation descriptor changed.
- Computer-account creation by ordinary domain user.
- New machine account immediately requests tickets to high-value services.
- Review `ms-DS-MachineAccountQuota`; set to `0` unless user-created computer accounts are required.
- Alert on any RBCD descriptor change outside approved deployment tooling.

### Collection and tooling

- PowerShell:
  - `4103`: module logging.
  - `4104`: script-block logging.
  - AMSI and EDR telemetry for PowerView, StandIn, and Rubeus signatures.
- LDAP:
  - Broad ACL enumeration.
  - Repeated reads of delegation and security-descriptor attributes.
- Process/network:
  - `dacledit.py`, Python, or Impacket execution from unmanaged hosts.
  - SMB, LDAP, or LDAPS access to DCs from unusual Linux systems.
  - Command lines containing `msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-AllowedToDelegateTo`, `nTSecurityDescriptor`, or `servicePrincipalName`.

---

## [reasoning trace]


