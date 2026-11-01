# bounty-methodology — bb

# Metodologi Hunting — Red Team Internal

## 1. Pemilihan Program (Target Selection)

Skor program dihitung sebelum masuk hunter loop. Bobot default:

| Faktor | Bobot | Skor 1 (buruk) | Skor 3 (sedang) | Skor 5 (baik) |
|---|---|---|---|---|
| Usia program | 15% | < 30 hari | 1–6 bln | > 12 bln, scope stabil |
| Scope luas | 25% | 1 domain, wildcard sempit | 5–20 domain | wildcard `*.tld`, API+web+mobile |
| Payout | 25% | none/points | $50–500 | > $1000 critical |
| Duplikat rate | 15% | known crowded | mixed | niche stack / produk baru |
| Responsiveness | 10% | > 30 hari | 7–30 hari | < 7 hari |
| Asset baru | 10% | static | minor update | merger/akuisisi/replatform |

**Rule of thumb:** skor ≥ 4.0 → masuk sprint. 3.0–4.0 → queue time-boxed 2 jam. < 3.0 → skip.

Program **baru** (aging < 60 hari) = dup rate rendah tapi payout sering belum teruji. Prioritaskan wildcard scope (asset enumeration > single asset deep-dive) karena ROI enumeration tinggi di fase awal.

Program **scope luas** = butuh subdomain/asset inventory otomatis dulu sebelum hunting. Tanpa inventory, waktu habis di recon.

```bash
# inventory cepat — subfinder v2.6 + dnsx + httpx
subfinder -d target.tld -all -silent | dnsx -silent -a -resp \
  | httpx -silent -sc -title -tech-detect -td -threads 100 \
  -o inventory.txt
```

Output `inventory.txt` → filter `[nginx 1.25]`, `[Chrome 131]` di UA, `[Windows 11 24H2]` di banner RDP tidak relevan — fokus ke tech stack web.

## 2. Time-Boxing

| Fase | Durasi | Exit criteria |
|---|---|---|
| Recon/asset enum | 2 jam | inventory + tech tags |
| Surface mapping (param, endpoint, auth flow) | 3 jam | endpoint list + auth boundary |
| Deep-dive 1 teknik | 4 jam | PoC atau null result terdokumentasi |
| Tulis + submit | 1 jam | report + ledger entry |

Blok 10 jam per sprint per program. Jika deep-dive > 6 jam tanpa PoC → **pivot** (gelombang kedua teknik lain), bukan lanjut. Estimasi overrun adalah sinyal program salah pilih, bukan kurang gigih.

Timebox tracker:

```bash
# timer sprint 10 jam, log ke ledger
START=$(date +%s); PHASE=recon
check() { echo "$(date -u +%FT%TZ) phase=$PHASE elapsed=$(( ($(date +%s)-START)/60 ))m"; }
```

## 3. Triage Cepat

Setiap finding masuk triage 15 menit. Klasifikasi biner dulu, validasi detail belakangan.

| Signal | Aksi |
|---|---|
| Reflected input, tidak ada filter → XSS | validasi di Chrome 131 + Firefox 133 (bukan cuma curl) |
| 401/403 → 200 dengan header tambahan | cek `X-Forwarded-For: 127.0.0.1`, `X-Original-URL` |
| SQLi error string (`SQLSTATE`, `ORA-`) | konfirmasi time-based, bukan hanya union |
| SSRF callback | DNS + HTTP callback di webhook kontrol |
| IDOR object ID increment | cek 3 ID valid sebelum klaim |
| Subdomain takeover | fingerprint `nginx 1.25` default page ≠ takeover; cek CNAME ke `*.herokuapp.com`, `*.s3.amazonaws.com` |

**Aturan triage:** finding tanpa reproduksi deterministik **tidak** masuk ledger sebagai temuan — masuk `candidate`. Validasi pakai browser + curl, karena banyak WAF (Cloudflare, Akamai) memblokir curl default.

```bash
# curl dengan fingerprint browser untuk lulus WAF
curl -s -o /dev/null -w "%{http_code}\n" \
  -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' \
  -H 'Accept: text/html,application/xhtml+xml' \
  https://target.tld/path
```

Apa yang dikirim: header UA + Accept lengkap. Apa yang muncul: 200 (vs 403 dengan curl default). Kenapa berhasil: WAF rule default menolak UA `curl/*`. Kenapa gagal: target pakai mTLS atau Cloudflare Bot Management — UA spoofing tidak cukup, perlu TLS fingerprint (`curl-impersonate`).

## 4. Kolaborasi 4 Otak

Empat hunter paralel, peran tetap per sprint (rotasi antar sprint supaya tidak silo):

| Otak | Peran | Output |
|---|---|---|
| A — Recon | asset enum, tech fingerprint, endpoint discovery | inventory + param list |
| B — Auth/Session | auth flow, JWT/cookie, IDOR/priv-esc, SSO | boundary map + PoC auth |
| C — Injection/Server | XSS, SSTI, SQLi, SSRF, file upload, deser | payload library + PoC |
| D — Business Logic | state machine, race, payment, coupon, workflow | sequence abuse + PoC |

Sinkronisasi tiap 2 jam: 10 menit — tiap otak share satu artefak, bukan cerita. Artefak wajib masuk ledger sebelum sync. Tanpa artefak = dianggap belum dikerjakan.

**Aturan kolaborasi:**
- Otak B → C handoff: endpoint auth berhasil = titik injeksi untuk C.
- Otak D butuh inventory dari A, bukan hasil C.
- Konflik scope (dua otak di endpoint sama) → ledger kosong = boleh masuk, ledger terisi = review saja.

## 5. Ledger Temuan

Satu file per program, format TSV, append-only. Skema:

```
ts         | otak | host        | endpoint              | teknik      | status    | severity | artifact
2026-01-12T03:41Z | C | api.tld     | /v1/export            | ssrf        | candidate | -        | /tmp/ssrf-001.txt
2026-01-12T04:02Z | B | app.tld     | /admin/users/123      | idor        | confirmed | high     | /tmp/idor-002.txt
```

Status: `candidate` → `confirmed` → `submitted` → `triaged` → `dup`/`paid`.

Backing store SQLite untuk query metrik:

```bash
sqlite3 ledger.db "CREATE TABLE findings(ts TEXT, otak TEXT, host TEXT, endpoint TEXT, teknik TEXT, status TEXT, sev TEXT, artifact TEXT);"
sqlite3 ledger.db "SELECT teknik, status, COUNT(*) FROM findings GROUP BY teknik,status;"
```

**Gate submit:** `confirmed` minimal 3 reproduksi deterministik (cookie baru, IP berbeda jangan — session lama). Submit dalam < 30 menit setelah confirmed, sebelum dup.

## 6. Checklist Harian

- [ ] Cek program aging (ada program baru < 7 hari? tambah ke queue)
- [ ] Refresh inventory (`subfinder` delta) — asset baru = peluang sebelum crowded
- [ ] Sync 4 otak: 1 artefak per otak, 10 menit
- [ ] Triage semua `candidate` hari sebelumnya (15 menit masing-masing)
- [ ] Ledger: minimal 2 entry baru per otak
- [ ] Cek notifikasi program (scope change, payout change, resolved dup)
- [ ] Submit minimal 1 `confirmed` sebelum end of day
- [ ] Blok pivot: ada deep-dive > 6 jam tanpa PoC? cut + pivot

## 7. Metrik

| Metrik | Formula | Target |
|---|---|---|
| Finding rate | findings_confirmed / hr_hunting | ≥ 0.3 |
| Valid rate | paid / submitted | ≥ 0.6 |
| Dup rate | dup / submitted | ≤ 0.25 |
| Time-to-submit | ts_submit − ts_confirmed | < 30 menit |
| Time-to-triage | ts_triaged − ts_submitted | < 72 jam |
| Pivot rate | pivots / deep_dive | 0.2–0.4 (terlalu rendah = gigih buta, terlalu tinggi = tidak fokus) |
| Recon coverage | assets_inventoried / assets_in_scope | ≥ 0.85 |
| Payout/hr | total_payout / hr_hunting | monotonic per sprint |

Query mingguan:

```bash
sqlite3 ledger.db "SELECT SUM(sev='high' OR sev='critical')*1.0/COUNT(*) FROM findings WHERE status IN ('paid','submitted');"
```

---

## Jebakan Operasional yang Bikin Gagal di Lapangan

1. **Enumeration tanpa filter tech** — inventory 50k subdomain, 90% parked page `nginx 1.25` default. Tanpa `httpx -td`, waktu deep-dive habis di halaman kosong. Filter: `-fc 404,403 -mc 200,401,500`.
2. **WAF memblokir curl, bukan browser** — laporan "tidak bisa reproduksi" karena hanya pakai curl default. Pakai `curl-impersonate` (chrome131 preset) atau browser + DevTools copy-as-cURL.
3. **Dup karena submit lambat** — finding `confirmed` didiamkan > 2 jam untuk "rapikan laporan" = kalah race. Submit minimal dulu, edit belakangan (banyak platform izinkan edit < 24 jam).
4. **Overrun deep-dive** — satu teknik > 6 jam tanpa PoC terus dilanjut = sprint 10 jam habis di satu endpoint. Pivot wajib, bukan opsional.
5. **Ledger tidak append-only** — edit/overwrite entry lama menghapus jejak `candidate` yang sebenarnya bisa di-upsell setelah dapat teknik baru. Append + status transition saja.
6. **Kolaborasi tanpa artefak** — sync 4 otak jadi sesi cerita, keputusan berdasarkan ingatan bukan bukti. Artefak wajib sebelum sync.
7. **Timebox tidak di-log** — tanpa timestamp, estimasi overrun tidak terdeteksi. Timer wajib di shell, log ke ledger.
8. **Triage IDOR dengan satu ID** — object ID valid sekali ≠ IDOR. Wajib 3 ID milik user berbeda + konfirmasi akses lintas akun di browser (bukan hanya curl, karena session cache).
9. **Subdomain takeover false positive** — `nginx 1.25` default page di `*.herokuapp.com` adalah 404 Heroku, bukan takeover. Wajib cek HTTP response body + CNAME chain, bukan hanya status 200.

---

## [reasoning trace]


