# w2-android-tamper — mobile

# Android App Pentest Flow — Referensi Red Team

## 1. Environment Baseline

| Tool | Versi diuji | Catatan |
|---|---|---|
| apktool | 2.9.3 | zipalign dipisah, pakai `apksigner` manual |
| uber-apk-signer | 1.3.0 | `-a` auto keystore debug |
| objection | 1.11.0 | butuh frida 16.x |
| frida | 16.2.1 (client), 16.2.1-server | versi WAJIB match client⇄server |
| JADX | 1.5.0 | decompile untuk cari lokasi pinning |
| adb | platform-tools 35.0.2 | |
| Target uji | Android 13 (API 33), Android 14 (API 34) | API 34 memperketat `dlopen` non-SDK |
| Host | Windows 11 24H2 / Kali 2024.4 | |

---

## 2. Unpack APK

```bash
apktool d -f -r target.apk -o target_smali
# -r = jangan decode resources (percepat; hilangkan bila butuh ubah manifest/res)
```

Cek kandidat pinning (Occam's razor — cari string, jangan tebak):

```bash
grep -rInE "CertificatePinner|TrustManager|X509TrustManager|checkServerTrusted|sha256/|pin-set" target_smali/smali* 2>/dev/null | head -50
grep -rIn "network_security_config" target_smali/AndroidManifest.xml
```

Kalau `network_security_config` muncul → cek `res/xml/network_security_config.xml` (butuh decode resources: `apktool d -f target.apk -o target_full`).

---

## 3. Smali Patch — Lokasi SSL Pinning Umum

### 3.1 OkHttp `CertificatePinner` (paling sering di app modern)

Cari kelas yang meng-instansiasi `CertificatePinner`:

```bash
grep -rIn "Lokhttp3/CertificatePinner;" target_smali/smali*/ | grep -i "new-instance\|invoke-direct"
```

Target: method `check` di `okhttp3/CertificatePinner.smali`. Patch dua method ini jadi no-op:

**`check(Ljava/lang/String;Ljava/util/List;)V`** (varian lama, OkHttp ≤4.9) — ganti body:

```smali
.method public final check(Ljava/lang/String;Ljava/util/List;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = { "Ljava/lang/String;", "Ljava/util/List<",
            "Ljava/security/cert/Certificate;>;" }
    .end annotation
    return-void
.end method
```

**`check(Ljava/lang/String;Ljava/util/List;Lkotlin/jvm/internal/DefaultConstructorMarker;)V`** (varian Kotlin bridge) — sama, `return-void`.

Kalau app pakai builder + custom `CertificatePinner.Builder().add(...)`, kadang lebih gampang patch pemanggil `new-instance Lokhttp3/CertificatePinner$Builder;` → ganti jadi `new-instance Lokhttp3/CertificatePinner;` dengan `Builder` default kosong. **Lebih rapuh** — utamakan patch `check`.

### 3.2 Custom `X509TrustManager`

Cari:

```bash
grep -rIn "checkServerTrusted" target_smali/smali*/ | grep -v "Ljava/security/cert/X509Certificate"
```

Patch body method `checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V`:

```smali
.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .locals 0
    return-void
.end method
```

Dan `getAcceptedIssuers()[Ljava/security/cert/X509Certificate;`:

```smali
.method public getAcceptedIssuers()[Ljava/security/cert/X509Certificate;
    .locals 1
    const/4 v0, 0x0
    new-array v0, v0, [Ljava/security/cert/X509Certificate;
    return-object v0
.end method
```

### 3.3 HostnameVerifier

Cari `Ljavax/net/ssl/HostnameVerifier;` → patch `verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z`:

```smali
.method public verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method
```

### 3.4 Flutter (BoringSSL) — patch di native, bukan smali

Smali patch **tidak** menyentuh pinning Flutter (`libflutter.so`). Pakai objection/Frida (lihat §5) atau patch `libflutter.so` dengan hex-edit `ssl_crypto_x509_session_verify_cert_chain` → `return 1`. Out of scope bab ini.

---

## 4. Rebuild + Sign

```bash
apktool b target_smali -o target_patch.apk

# zipalign WAJIB sebelum sign (apksigner butuh aligned)
zipalign -p -f -v 4 target_patch.apk target_aligned.apk

# uber-apk-signer (auto pakai debug keystore kalau -a)
java -jar uber-apk-signer-1.3.0.jar \
  --apks target_aligned.apk \
  --allowResign \
  --overwrite \
  --out ./signed
```

Output: `./signed/target_aligned-aligned-signed.apk`.

Verifikasi:

```bash
apksigner verify --print-certs signed/target_aligned-aligned-signed.apk
```

**Install** (uninstall dulu; signature berubah):

```bash
adb uninstall com.target.pkg
adb install -r signed/target_aligned-aligned-signed.apk
# kalau INSTALL_FAILED_UPDATE_INCOMPATIBLE → adb uninstall residual
# kalau INSTALL_FAILED_TEST_ONLY → apksigner sign --ks debug.keystore (bukan uber -a)
```

---

## 5. Frida Injection — Dua Jalur

### 5.1 objection patchapk (Frida gadget embedded)

```bash
# Asumsi: target.apk original (belum smali-patch) ATAU sudah re-sign
objection patchapk --source target.apk --architecture arm64-v8a --skip-resources
# output: target.objection.apk
```

Lalu install & spawn:

```bash
adb install -r target.objection.apk
objection -g com.target.pkg explore --startup-command "android sslpinning disable"
```

Cek gadget loaded:

```bash
adb shell dumpsys package com.target.pkg | grep -i "primaryCpuAbi"
# atau logcat:
adb logcat | grep -i "frida\|gadget"
```

**Batas**: patchapk gagal kalau APK punya **split APKs** (base + config) → gabung dulu dengan `apkeditor`/`APKEditor.jar m -i splitdir -o merged.apk`. Gagal juga pada APK dengan **v4 signature only** / Play Integrity hard-gate pada signature asli.

### 5.2 frida-server (rooted / emulator)

```bash
# 1) cek arsitektur device
adb shell getprop ro.product.cpu.abi     # arm64-v8a | x86_64

# 2) push frida-server versi SAMA dengan client
adb push frida-server-16.2.1-android-arm64 /data/local/tmp/fs
adb shell "chmod 755 /data/local/tmp/fs"

# 3) jalankan (root)
adb shell "su -c '/data/local/tmp/fs -l 0.0.0.0:27042 &'"
adb forward tcp:27042 tcp:27042
frida-ps -U                              # harus list proses

# 4) spawn target (jangan launch manual, hook awal hilang)
frida -U -f com.target.pkg -l hooks.js --no-pause
# atau objection:
objection -g com.target.pkg explore
```

**Versi mismatch** = error `Failed to load script`/`unable to connect`. Cek:

```bash
frida --version
adb shell "/data/local/tmp/fs --version"
```

---

## 6. Root / Tamper Detection Bypass Patterns

### 6.1 Magisk (renamed + DenyList) — prasyarat

1. Magisk app → **Settings → Hide the Magisk app** → rename jadi mis. `Settings` / `SystemUI` (nama tidak mengandung "magisk").
2. **DenyList** → tambah `com.target.pkg` (dan `com.google.android.gms` kalau Play Integrity dicek).
3. **Zygisk** ON.
4. Reboot.

Verifikasi di device:

```bash
adb shell "su -c 'magisk --denylist ls'"
```

### 6.2 SafetyNet / Play Integrity — reality check

- **SafetyNet Attestation API**: deprecated 2024, tapi banyak app lama masih panggil. Ditolak kalau `basicIntegrity=false` → Magisk DenyList + renamed + **Play Integrity Fix (PIF)** module (fork terbaru, mis. `chiteroman/PlayIntegrityFix` atau `PlayIntegrityFix-next`) yang memalsukan fingerprint device ke build Google-certified.
- **Play Integrity API** (pengganti): `MEETS_DEVICE_INTEGRITY` hanya lolos kalau modul + fingerprint OK. `MEETS_STRONG_INTEGRITY` butuh hardware keybox — **tidak bisa di-bypass software-level** di device rooted; untuk itu pakai **device fisik unroot + emulator berbeda** untuk uji.
- Cek status lewat `Play Integrity API Checker` / `YASNAC` di device, **bukan** dari host.

### 6.3 Frida-detection bypass (JS, sample)

App yang deteksi `frida-server` via `/proc/self/maps`, `ptrace`, nama port 27042 — hook:

```javascript
// hooks/frida_hide.js
Java.perform(function () {
  var String = Java.use("java.lang.String");
  var File = Java.use("java.io.File");

  // Sembunyikan string "frida" dari File.exists / String.contains
  var origContains = String.contains;
  String.contains.overload("java.lang.CharSequence").implementation = function (s) {
    var r = this.contains(s);
    try {
      if (s && (s.toString().toLowerCase().indexOf("frida") >= 0 ||
                s.toString().toLowerCase().indexOf("gum") >= 0 ||
                s.toString().toLowerCase().indexOf("xposed") >= 0)) {
        return false;
      }
    } catch (e) {}
    return r;
  };

  // Sembunyikan path frida di File.exists
  var origExists = File.exists;
  File.exists.implementation = function () {
    var p = this.getAbsolutePath();
    if (p && (p.indexOf("frida") >= 0 || p.indexOf("gum-js") >= 0 ||
              p.indexOf("magisk") >= 0 || p.indexOf("su") >= 0 && p.endsWith("/su"))) {
      return false;
    }
    return origExists.call(this);
  };
});
```

Jalankan bareng hook target:

```bash
frida -U -f com.target.pkg -l hooks/frida_hide.js -l hooks/sslpinning.js --no-pause
```

---

## 7. Hook JS Umum (siap paste)

### 7.1 OkHttp — log + bypass pinning

```javascript
// hooks/okhttp.js — OkHttp 4.x
Java.perform(function () {
  try {
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (h, c) {
      console.log("[okhttp] bypass pin: " + h);
      return;
    };
    console.log("[okhttp] CertificatePinner patched");
  } catch (e) { console.log("[okhttp] pinner not found: " + e); }

  try {
    var Builder = Java.use("okhttp3.OkHttpClient$Builder");
    Builder.build.implementation = function () {
      var client = this.build();
      return client;
    };
  } catch (e) {}

  // Log semua request
  try {
    var RealCall = Java.use("okhttp3.internal.connection.RealCall");
    RealCall.execute.implementation = function () {
      console.log("[okhttp] exec: " + this.request().url().toString());
      return this.execute();
    };
  } catch (e) {}
});
```

### 7.2 Firebase — bypass App Check / log token

```javascript
// hooks/firebase.js
Java.perform(function () {
  try {
    var FIS = Java.use("com.google.firebase.installations.FirebaseInstallations");
    FIS.getId.implementation = function () {
      var t = this.getId();
      console.log("[firebase] installation id task");
      return t;
    };
  } catch (e) {}

  try {
    var AppCheck = Java.use("com.google.firebase.appcheck.AppCheckTokenResult");
    AppCheck.getToken.implementation = function () {
      var t = this.getToken();
      console.log("[firebase] appcheck token: " + t);
      return t;
    };
  } catch (e) {}

  // Bypass App Check enforcement di Firestore (kalau ada gate)
  try {
    var FirebaseApp = Java.use("com.google.firebase.FirebaseApp");
    console.log("[firebase] app name: " + FirebaseApp.getInstance().getName());
  } catch (e) {}
});
```

### 7.3 Keystore extract (AndroidKeyStore)

```javascript
// hooks/keystore.js — dump alias & private key material saat app ambil
Java.perform(function () {
  var KeyStore = Java.use("java.security.KeyStore");
  KeyStore.getKey.overload("java.lang.String", "[C").implementation = function (alias, pwd) {
    var k = this.getKey(alias, pwd);
    if (k) console.log("[keystore] alias=" + alias + " keyClass=" + k.getClass().getName());
    return k;
  };

  var KeyStoreSpi = Java.use("java.security.KeyStoreSpi");
  // AndroidKeyStore entry saat di-unlock
  try {
    var AndroidKS = Java.use("android.security.keystore.AndroidKeyStoreSpi");
    AndroidKS.engineGetKey.implementation = function (alias, pwd) {
      var k = this.engineGetKey(alias, pwd);
      if (k) {
        console.log("[AndroidKS] alias=" + alias);
        console.log("[AndroidKS] type=" + k.getAlgorithm());
      }
      return k;
    };
  } catch (e) { console.log("[AndroidKS] " + e); }

  // Cipher: dump IV & plaintext setelah decrypt
  var Cipher = Java.use("javax.crypto.Cipher");
  Cipher.doFinal.overload("[B").implementation = function (data) {
    var out = this.doFinal(data);
    var mode = this.getOpmode(); // 2=DECRYPT
    if (mode === 2) {
      console.log("[cipher] decrypted: " + Java.array('byte', out));
    }
    return out;
  };
});
```

**Batas keras**: key dengan `setIsStrongBoxBacked(true)` atau `setUserAuthenticationRequired(true)` **tidak extractable** — cipher berjalan di TEE/StrongBox, Frida hanya melihat input/output, bukan key material. Untuk itu perlu ekstrak di device **unlocked + user auth** dengan hook pada `Cipher.doFinal` (lihat di atas) — bukan `getKey`.

---

## 8. Jebakan Operasional (yang bikin teknik ini gagal di lapangan)

| # | Jebakan | Gejala | Mitigasi |
|---|---|---|---|
| 1 | **Split APK / App Bundle** | `apktool d base.apk` sukses, rebuild `INSTALL_FAILED_INVALID_APK` | Merge dulu: `java -jar APKEditor.jar m -i splitdir -o merged.apk`, baru apktool |
| 2 | **Frida versi mismatch** | `Failed to spawn: unable to connect to remote frida-server` | Lock versi client & server; jangan pakai `pip install frida-tools` tanpa pin |
| 3 | **Frida server tidak match ABI** | proses crash / `exited with code 1` | `adb shell getprop ro.product.cpu.abi` → push `arm64`/`x86_64` yang benar |
| 4 | **Zipalign sebelum sign** | `INSTALL_PARSE_FAILED_NO_CERTIFICATES` | Urutan WAJIB: buid → zipalign → apksigner/uber. Bukan sebaliknya |
| 5 | **`android:debuggable=false` + `ptrace` dari app** | Frida attach → app langsung kill | Pakai `frida -f` spawn (bukan attach), atau patch manifest `debuggable="true"` lalu re-sign (memicu deteksi lain) → trade-off |
| 6 | **Play Integrity `STRONG_INTEGRITY`** | `basicIntegrity=true`, `deviceIntegrity=false`, `strongIntegrity` tidak pernah true | Hardware keybox — **tidak bisa** software bypass. Uji di device Google-certified unroot, atau terima partial |
| 7 | **SafetyNet deprecated** | `YASNAC` crash / tidak jalan | Beralih ke Play Integrity checker; API `attest` sudah mati |
| 8 | **Flutter / React Native gRPC** | smali patch `CertificatePinner` tidak effect, traffic tetap ditolak | Flutter: patch `libflutter.so` atau Frida `BoringSSL` hooks; RN: hook `com.facebook.react.modules.network` |
| 9 | **Certificate pinning di native (conscrypt custom)** | Frida `sslpinning disable` tidak cukup | Butuh hook `SSL_CTX_set_custom_verify` di `libssl.so` — atau `frida-trace -I libssl.so` |
| 10 | **Signature check internal** | App crash setelah re-sign (checksum APK / cert hash hardcoded) | Patch method `getPackageInfo(...).signatures` → return signature asli, atau hook di Frida `PackageManager` |
| 11 | **`INSTALL_FAILED_TEST_ONLY`** | uber-apk-signer `-a` tidak set flag | `apksigner sign --ks debug.keystore` manual, atau `adb install --bypass-low-target-sdk-block` (bukan untuk test-only) |
| 12 | **`/data/local/tmp` noexec (Android 10+ beberapa OEM)** | `frida-server: Permission denied` | Push ke `/data/local/tmp` dengan `chmod 755` biasanya OK; kalau OEM block, `cp` ke `/data/adb/` (Magisk) |
| 13 | **Magisk DenyList tidak isolate** | Play Integrity lihat `init.rc` Magisk | Aktifkan **Zygisk** + **DenyList enforce**, install **PIF** dengan fingerprint device Google-Play-certified terbaru |
| 14 | **Renamed Magisk tetap terdeteksi** | App crash di `onCreate` cek root | Cek juga `ro.debuggable`, `ro.secure`, `su` path — bukan cuma nama package. Combine PIF + Shamiko |
| 15 | **OKHttp 5.x** | `CertificatePinner.check` signature berubah | Cek versi di smali: OkHttp 5 ganti ke `CertificatePinner$Companion` — patch `Companion.check` |
| 16 | **Backup/restore state (dropbox) restore stale APK** | Install sukses tapi versi lama jalan | `adb shell pm clear com.target.pkg` + `adb uninstall` sebelum install baru |
| 17 | **APK di-protect (DexGuard, Bangcle, Jiagu)** | apktool decode → smali obfuscated / native stub | Unpack pakai `frida-dump` (hook `DexFile.loadDex`) atau `frida-dexdump`; jangan buang waktu patch smali stub |
| 18 | **`usesCleartextTraffic=false` (API 28+)** | intercept proxy HTTP gagal | Patch `AndroidManifest.xml` → `android:usesCleartextTraffic="true"`, atau pasang user CA + `network_security_config` override |

---

---

## [reasoning trace]


