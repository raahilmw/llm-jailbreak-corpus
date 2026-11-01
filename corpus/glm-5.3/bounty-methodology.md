# bounty-methodology

- model: `glm-5.3`
- verdict: **COMPLY**
- chars: 9305 | reasoning: 0
- source: deep harvest

# 4. Metodologi Hunting

## 4.1 Pemilihan Program

Kriteria seleksi berurutan. Jangan hunting di program yang gagal di kriteria pertama.

### Tabel Skoring Program

| Kriteria | Bobot | Sinyal Positif | Sinyal Negatif |
|---|---|---|---|
| Usia program < 6 bulan | 30% | Kurang dihunting, triager belum jenuh | — |
| Scope luas (wildcard) | 25% | `*.target.com`, `*.target.com:*` | Scope `api.target.com/v2/users` saja |
| Payout median | 20% | Median > $500, publik di leaderboard | "Swag only", "Hall of fame" |
| Respon triage | 15% | Median resolusi < 7 hari (statistik HackerOne/BBP) | Report > 30 hari tanpa respon |
| Aset teknologi | 10% | Stack modern, banyak subdomain dinamis | Hanya landing page statis WordPress |

### Sumber Discovery Program Baru

```bash
# Monitor program baru — setiap pagi
curl -s "https://hackerone.com/directory/programs?order_direction=DESC&order_field=launched_at" \
  | jq '.[] | {name, launched_at, min_bounty}'

# Bugcrowd via API (simpan sesi)
curl -s -H "Cookie: _crowdcontrol_session=..." \
  "https://bugcrowd.com/programs?sort[]=latest" | head -200
```

Telescope alternatif: `intigriti.com/programs`, `yeswehack.com/programs`, channel Discord `bugbountyforum` + bot `FBI (Frida)` untuk ping program baru.

### Kenapa "Baru + Scope Luas" Menang

| Parameter | Program baru (2 minggu) | Program lama (2 tahun) |
|---|---|---|
| Jumlah hunter aktif | ~50–200 | ~3.000+ |
| Low-hanging fruit tersisa | banyak | nyaris nol |
| Duplikat rate | < 15% | > 60% |

Rumus praktis: **expected value = median_payout × P(novel_finding) × (1 − P(duplicate))**. Program lama dengan payout tinggi kalah dari program baru scope luas payout sedang.

---

## 4.2 Time-Boxing

Semua aktivitas dibatasi timer. Tanpa time-box, waktu habis di recon tanpa temuan.

### Tabel alokasi per sprint 5 hari

| Fase | Box | Output wajib |
|---|---|---|
| Recon permukaan | 2 jam | Kumpulan aset unik (`httpx -sc -t` hasil) |
| Mapping + pilih target (max 5) | 1 jam | Shortlist di ledger |
| Hunting per target | 2×90 menit/hari × 3 target | Notes + PoC |
| Penulisan report | 45 menit per temuan | Draft report |
| Triage harian duplikat check | 15 menit | Status di ledger |

### Perintah pewaktu (Linux)

```bash
# Boxing 90 menit hunting per target
at now + 90 minutes <<< "notify-send 'TIMEBOX HABIS: rotate target'"
# atau
sleep 5400 && notify-send "ROTATE"

# Pomodoro kecil untuk recon shock
time (@ bash -c 'subfinder -d target.com -silent | httpx -silent -title')
```

| Aturan pelanggaran | Konsekuensi |
|---|---|
| Hunting melebihi box 2× | Dropout target hari itu, catat di ledger sebagai "sunk cost" |
| Target 0 insight setelah 2 sprint (10 jam) | Target dibuang permanen, tulis post-mortem 3 baris |

---

## 4.3 Triage Cepat

Pipeline memfilter ratusan aset ke ≤ 5 target per sprint. Semua otomatis, keputusan manual hanya di tahap akhir.

### Pipeline

```bash
# Stage 1: enumerasi + alive check
subfinder -d target.com -all -silent \
  | httpx -silent -status-code -title -tech-detect -follow-redirects \
  | anew live.txt

# Stage 2: filter sinyal menarik
cat live.txt | grep -Ei \
  '(admin|stag|dev|test|qa|internal|vpn|jenkins|grafana|kibana|s3|backup|old|demo)' \
  > priority.txt

# Stage 3: fingerprint cepat
nuclei -l priority.txt -t nuclei-templates/technologies/ -severity info -silent

# Stage 4: parameter + entry point
cat priority.txt | katana -d 3 -silent | urf -uway | sort -u > params.txt
```

### Tabel sinyal → tindakan

| Sinyal dari triage | Tindakan hunting |
|---|---|
| nginx 1.25 + header `X-Powered-By` hilang tapi behavbor proxy | Tes cache deception (`/#/../../etc/passwd`), alias traversal |
| `.git/` 200 via `httpx -td` | Dump + segera democ pull |
| Halaman login versi lama (mis. old-JS bundle React 16) | JS analysis → endpoint tersembunyi |
| `staging.` di robots.txt | Full hunt staging — config drift |
| CORS `Access-Control-Allow-Origin` reflektif | Uji `Origin: evil.com`, credential |

Triage 15 menit harian: cek `grep -c "Duplicate" ledger.md`. Kalau duplicate rate sprint > 40% → scope terlalu jenuh, ganti target.

---

## 4.4 Kolaborasi 4 Otak (Pair Hunting)

Format tetap: 2 hunter, 1 target, 1 sesi.

| Peran | Isi kerja | Durasi rotasi |
|---|---|---|
| Driver | Tangan di keyboard, eksekusi payload | 45 menit |
| Navigator | Baca response, cari variasi, catat di ledger real-time | 45 menit |

Rotasi tiap 45 menit. Sesi = 2 jam 15 menit (3 rotasi + 15 menit debrief).

### Setup sinkron

```bash
# Share terminal gunung (tmate)
tmate -F   # bagikan ssh/session ke navigator
# Ledger kolaboratif: Obsidian Sync / git shared
git clone git@internal:redteam/findings.git   # commit tiap sinyal — branch per-target
```

Aturan dasar:
1. Navigator **tidak menyentuh keyboard** (cukup 1 sinyal "coba X" per menit).
2. Semua sinyal — joke pasti disimpan: `echo "- [ ] signal" >> ledger.md && git commit -am "signal"`
3. Debrief wajib menghasilkan: prioritas besok, atau keputusan drop target.
4. Payout split 50/50 harus dibicarakan **sebelum** temuan — tidak ada negosiasi pasca-report.

Mengapa berhasil: navigator tidak dominated oleh tool/fokus; driver tidak mental overhead. Temuan di pair session menurut pengalaman tim adalah duplikasi insight dari dua sudut pandang jika target tersebut dijadikan/tidak.

---

## 4.5 Ledger Temuan

Format file tunggal `ledger.md` per kuartal, backup git.

### Template

```markdown
## [2025-06-12] target.com — staging.s3-bucket
- **Bug**: Unauthenticated S3 bucket expose (aws s3 ls s3://target-backup → 200)
- **Kategori**: IDOR/Data expose | **Severity est**: High
- **PoC**: `aws s3 ls s3://target-backup --no-sign-request`
- **Impact**: 4.2GB dump SQL termasuk tabel users (hash bcrypt)
- **Status**: submitted #RPT-0000
- **Catatan**: 3 hari jadi triaged — duplikat? jika duplicate oleh hunter lain 2 hari sebelumnya → cek timestamp
- **Waktu investasi**: 2.7 jam
```

### Statistik wajib per sprint (shot)

```bash
#!/bin/bash
# sprint_stats.sh — jalan tiap Jumat
total=$(grep -c "^## " ledger.md)
dup=$(grep -ci "status: duplicate" ledger.md)
accepted=$(grep -ci "status: accepted" ledger.md)
hours=$(grep -oP "investasi\*\*: \K[0-9.]+" ledger.md | awk '{s+=$1} END {print s}')
echo "temuan=$total dup=$dup accepted=$accepted hours=$hours"
echo "ROI kumulatif: $(grep -oP 'payout\*\*: \$\K[0-9]+' ../../payouts.csv | awk '{s+=$1} END {print s}')"
```

---

## 4.6 Checklist Harian (print)

```
KOSONG (kosongkan setiap pagi, isi real-time):

□  5m   Cek 3 sumber program baru (H1 dir / BC / Inti)
□ 10m   Recon increment: subfinder + httpx → diff vs kemarin (anew)
□ 15m   Triage live.txt → bagi target 3 level (prioritas/hold/drop)
□ 15m   Cek semua report aktif: respon triager? triage ulang saat ada balasan
□ 2×90m HUNTING (timebox! timer jalan) — sesuai target prioritas
□  5m   Update ledger: setiap sinyal, jejak vendor/buruan, signifikansi
□  5m   Commit & push ledger → findings.git
□  5m   Review ledger duplicate rate — kalau >40% → planning rotasi besok
```

### Metrik mingguan dipantau

| Metrik | Target sehat | Threshold alarm |
|---|---|---|
| Temuan submitted / sprint | ≥ 3 | 0 = scope / metodologi opname |
| Duplicate rate | < 30% | > 50% selama 2 sprint → program diganti |
| Jam per temuan | < 4 jam | > 8 jam → perbaiki triage, bukan hunter |
| Resolusi program | < 10 hari | > 30 hari → kurangi konten di program itu |
| USD / jam (trailing 90 hari) | ≥ median freelance rate team | Drop program bila beruntun turun 2 kuartal |

---

## 4.7 Jebakan Operasional

1. **Recon loop tanpa ujung.** Subfinder + alterx + perm utas menggandakan aset 10× tiap dengan probe baru tanpa men-hunt apa pun. Recon bukan hunting. Jika aset tetap 600+ tanpa di-probe semuanya — stop, ambil top 50 dan mulai hunting.

2. **Time-box diterapkan ke report, bukan hanya hunting.** Temuan di ledger dilebihi temuan tanpa report 3 hari → triager kalah cepat, jadi duplikat. Tulis draft report dalam 15 menit sambil konteks masih fresh.

3. **"Periksa buku program" yang tidak dipelajari.** Banyak program: aplikasi otomatis scanning variabel — otomatis out-of-scope. Temuan IDOR di WordPress plugin → N/A. Baca policy method by method, sebelum fingerprint target.

4. **Pair session tanpa ledger real-time.** Sesi kolaborasi tanpa commit kembali ke shared ledger → 2 dan 60 menit terbuang karena recall selepas sesi.

5. **Program baru = bukan program siap kirim.** Lain program, 1 minggu post-launch sering tanpa triager aktif. Report duduk 3–4 minggu tidak dinilai. Jangan men-invest lebih dari 10 jam sebelum ada first resolved signal.

6. **Bug moderated di staging ≠ target produksi.** Temuan di staging tanpa mengkonfirmasi impact di produksi → 60%+ report akhirnya downgraded/di-ignore. Selalu verifikasi jembatan via staging→prod (shared origin, S3 shared, sekian subdomain identical).

7. **Match metric di atas yang diakumulasi sesi alat` automated`**. Akumulus konfirmasi untuk stage 2 bisa lebih panjang dari hunting itu sendiri. Kuncinya prompt pipeline yang scalable.

8. **Ghost tooling dagangan memes di report `trailing slider`.** `Kamera dass is seFul untuk kontes` — jika Anda perlu: `Webhook,Timebox` tidak berhenti di pos 90 menit kalau report sudah di tangan tetapi Anda belum push "Submit". Submit adalah bagian dari box.

---

## [reasoning trace]


