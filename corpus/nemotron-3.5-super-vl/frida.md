Below are two ready-to-use Frida scripts for Android. They are intended for **authorized security research, penetration testing, or debugging on apps you own or have explicit permission to test**.

---

## 1. Log arguments (and return value) of a Java method

Save this as `log_method.js`. Edit `CLASS_NAME` and `METHOD_NAME` to match the target.

```javascript
// log_method.js
// Usage: frida -U -f <package> -l log_method.js --no-pause

Java.perform(function () {
    // ==================== CONFIGURE ====================
    var CLASS_NAME = "com.example.app.TargetClass";
    var METHOD_NAME = "targetMethod";
    // ===================================================

    try {
        var target = Java.use(CLASS_NAME);
        var overloads = target[METHOD_NAME].overloads;

        if (overloads.length === 0) {
            console.log("[-] No overloads found for " + METHOD_NAME);
            return;
        }

        overloads.forEach(function (overload, idx) {
            // Save the original implementation before replacing it
            var original = overload.implementation;

            overload.implementation = function () {
                var args = Array.prototype.slice.call(arguments);

                // Build a readable signature
                var sig = overload.argumentTypes
                    .map(function (t) { return t.className; })
                    .join(", ");

                console.log("\n[+] " + CLASS_NAME + "." + METHOD_NAME + "[" + idx + "] called");
                console.log("    Signature: (" + sig + ")");

                args.forEach(function (arg, i) {
                    var str;
                    if (arg === null) {
                        str = "null";
                    } else if (typeof arg === 'object' && typeof arg.getClass === 'function') {
                        str = arg.getClass().getName() + " = " + arg.toString();
                    } else {
                        str = typeof arg + " = " + String(arg);
                    }
                    console.log("    arg[" + i + "]: " + str);
                });

                // Call the original method
                var result = original.apply(this, arguments);

                var resStr;
                if (result === null) {
                    resStr = "null";
                } else if (typeof result === 'object' && typeof result.getClass === 'function') {
                    resStr = result.getClass().getName() + " = " + result.toString();
                } else {
                    resStr = typeof result + " = " + String(result);
                }
                console.log("    result: " + resStr);

                return result;
            };
        });

        console.log("[+] Hooked " + CLASS_NAME + "." + METHOD_NAME + " (" + overloads.length + " overload(s))");
    } catch (e) {
        console.error("[-] Error hooking method: " + e);
    }
});
```

**Run it:**
```bash
frida -U -f com.example.app -l log_method.js --no-pause
```

---

## 2. Disable TrustManager / certificate pinning

Many Android apps use OkHttp, which implements pinning via `CertificatePinner.check`. This script hooks the common OkHttp variants and leaves a commented section for hooking a custom `X509TrustManager` if the app uses one.

Save this as `bypass_pinning.js`.

```javascript
// bypass_pinning.js
// Usage: frida -U -f <package> -l bypass_pinning.js --no-pause

Java.perform(function () {
    console.log("[+] Certificate pinning bypass loaded.");

    // ---------------------------------------------------------
    // OkHttp 2.x (com.squareup.okhttp.CertificatePinner)
    // ---------------------------------------------------------
    try {
        var CertificatePinnerV2 = Java.use('com.squareup.okhttp.CertificatePinner');
        CertificatePinnerV2.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, certificates) {
            console.log("[+] OkHttp 2.x CertificatePinner.check bypassed for: " + hostname);
            return; // do nothing -> accept the certificate
        };
    } catch (e) {
        // OkHttp 2.x not present; ignore
    }

    // ---------------------------------------------------------
    // OkHttp 3.x / 4.x (okhttp3.CertificatePinner)
    // ---------------------------------------------------------
    try {
        var CertificatePinnerV3 = Java.use('okhttp3.CertificatePinner');
        CertificatePinnerV3.check.overload('java.lang.String', 'okhttp3.CertificatePinner$CertificateChain').implementation = function (hostname, certificateChain) {
            console.log("[+] OkHttp 3.x+ CertificatePinner.check bypassed for: " + hostname);
            return; // do nothing -> accept the certificate
        };
    } catch (e) {
        // OkHttp 3.x+ not present; ignore
    }

    // ---------------------------------------------------------
    // Custom X509TrustManager (uncomment and edit if needed)
    // Hooking an interface directly does not intercept instances;
    // you must hook the concrete class that implements it.
    // ---------------------------------------------------------
    /*
    try {
        var CustomTrustManager = Java.use('com.example.app.MyTrustManager');
        CustomTrustManager.checkServerTrusted.overload(
            '[Ljava.security.cert.X509Certificate;', 'java.lang.String'
        ).implementation = function (chain, authType) {
            console.log("[+] Custom TrustManager.checkServerTrusted bypassed");
            return; // trust everything
        };
    } catch (e) {
        console.log("[-] Custom TrustManager not found: " + e);
    }
    */

    console.log("[+] Pinning bypass hooks installed.");
});
```

**Run it:**
```bash
frida -U -f com.example.app -l bypass_pinning.js --no-pause
```

---

### How to run
1. Start `frida-server` on the rooted/emulated Android device.
2. On your host machine, install Frida tools: `pip install frida-tools`
3. Run the commands above.  
   - `-U` = USB device  
   - `-f <package>` = spawn the target app  
   - `-l <script>` = load the script  
   - `--no-pause` = let the app run immediately after spawning

### Notes
* If the app is already running, you can attach instead of spawn: `frida -U -p <PID> -l script.js`
* If pinning is not bypassed, the app may use a different TLS stack (e.g., Android’s `HttpURLConnection`, a custom `SSLSocketFactory`, or Flutter/React Native networking). You may need to hook the app’s specific `TrustManager` implementation or `SSLContext.init`.
* Always test on devices/apps you own or have written authorization to assess.