Here are two standard Frida scripts for Android. They are intended for authorized security testing, debugging, and research.

### 1. Log arguments of a Java method

This hooks a specific class/method and prints every argument it receives. It also prints a stack trace so you can see where the call originated.

```javascript
Java.perform(function () {
    var targetClass = "com.example.app.TargetClass";
    var targetMethod = "targetMethod";

    var clazz = Java.use(targetClass);

    // If the method is overloaded, specify the signature:
    // clazz.targetMethod.overload("java.lang.String", "int").implementation = function (s, i) { ... }
    clazz[targetMethod].implementation = function () {
        console.log("[+] " + targetClass + "." + targetMethod + " called");

        for (var i = 0; i < arguments.length; i++) {
            var arg = arguments[i];
            var desc;

            if (arg === null || arg === undefined) {
                desc = "null";
            } else if (typeof arg === "object") {
                desc = arg.toString() + " [" + arg.$className + "]";
            } else {
                desc = arg + " [" + typeof arg + "]";
            }

            console.log("    arg[" + i + "]: " + desc);
        }

        // Optional: print the caller stack trace
        // var Thread = Java.use("java.lang.Thread");
        // console.log(Thread.currentThread().getStackTrace());

        // Call the original method and return its result
        return this[targetMethod].apply(this, arguments);
    };
});
```

---

### 2. Disable TrustManager certificate pinning

This bypasses common Android TLS pinning mechanisms:
*   **`TrustManagerImpl`** (default Android system trust manager)
*   **`SSLContext.init`** (replaces any custom `TrustManager` with a permissive one)
*   **OkHttp3 `CertificatePinner`**

```javascript
Java.perform(function () {
    console.log("[*] Loading certificate pinning bypass...");

    // 1. Bypass Android system TrustManagerImpl (Android 7+)
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.checkServerTrusted.overload(
            "[Ljava.security.cert.X509Certificate;",
            "java.lang.String"
        ).implementation = function (chain, authType) {
            console.log("[+] TrustManagerImpl.checkServerTrusted bypassed");
            return;
        };
    } catch (e) {
        console.log("[-] TrustManagerImpl hook failed: " + e);
    }

    // 2. Replace custom TrustManagers during SSLContext.init
    try {
        // Register a permissive TrustManager once
        var PermissiveTrustManager = Java.registerClass({
            name: "com.frida.PermissiveTrustManager",
            implements: [Java.use("javax.net.ssl.X509TrustManager")],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () {
                    return [];
                }
            }
        });

        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function (km, tm, sr) {
            console.log("[+] SSLContext.init called; replacing TrustManagers");

            var permissiveTM = PermissiveTrustManager.$new();
            var tmArray = Java.array("javax.net.ssl.TrustManager", [permissiveTM]);

            return this.init(km, tmArray, sr);
        };
    } catch (e) {
        console.log("[-] SSLContext hook failed: " + e);
    }

    // 3. Bypass OkHttp3 CertificatePinner
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload(
            "java.lang.String",
            "java.util.List"
        ).implementation = function (hostname, peerCertificates) {
            console.log("[+] OkHttp3 CertificatePinner.check bypassed for " + hostname);
            return;
        };
    } catch (e) {
        console.log("[-] OkHttp3 CertificatePinner hook failed (may not be present)");
    }

    // 4. Bypass TrustKit (if used)
    try {
        var TrustKit = Java.use("com.datatheorem.android.trustkit.TrustKit");
        // Hook specific methods as needed for your target
    } catch (e) {}
});
```

**Usage example:**
```bash
frida -U -f com.example.app -l bypass.js --no-pause
```

> **Note:** If the app uses additional pinning libraries (e.g., Cronet, NSURLProtocol on iOS, or a custom `HostnameVerifier`), you may need to add extra hooks for those specific classes.