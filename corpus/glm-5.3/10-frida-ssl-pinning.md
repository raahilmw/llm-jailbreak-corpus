# Frida Scripts

## 1. Log Arguments of a Java Method

```javascript
Java.perform(function () {
    var TargetClass = Java.use("com.example.app.TargetClass");

    TargetClass.targetMethod.overload("java.lang.String", "int")
        .implementation = function (strArg, intArg) {

        console.log("[*] targetMethod called");
        console.log("    strArg: " + strArg);
        console.log("    intArg: " + intArg);

        // Optionally inspect object fields
        // console.log("    field: " + this.someField.value);

        var result = this.targetMethod(strArg, intArg);
        console.log("    return: " + result);
        return result;
    };
});
```

### Generic version (hook any overload automatically)

```javascript
Java.perform(function () {
    var TargetClass = Java.use("com.example.app.TargetClass");
    var overloads = TargetClass.myMethod.overloads;

    overloads.forEach(function (overload) {
        overload.implementation = function () {
            var args = [];
            for (var i = 0; i < arguments.length; i++) {
                args.push("arg" + i + ": " + arguments[i]);
            }
            console.log("[*] myMethod(" + args.join(", ") + ")");
            return this.myMethod.apply(this, arguments);
        };
    });
});
```

---

## 2. Disable TrustManager Certificate Pinning

```javascript
Java.perform(function () {
    console.log("[*] Starting SSL pinning bypass...");

    // --- TrustManagerImpl (Android default) ---
    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[+] Bypassing TrustManagerImpl (host: " + host + ")");
            return untrustedChain;
        };
    } catch (e) {
        console.log("[-] TrustManagerImpl not found: " + e);
    }

    // --- OkHttp CertificatePinner ---
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List")
            .implementation = function (hostname, peerCertificates) {
                console.log("[+] Bypassing OkHttp CertificatePinner: " + hostname);
                return;
            };
    } catch (e) {
        console.log("[-] OkHttp CertificatePinner not found: " + e);
    }

    // --- TrustManager (custom implementations) ---
    try {
        var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");

        var TrustManager = Java.registerClass({
            name: "com.frida.TrustAllManager",
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () {
                    return [];
                }
            }
        });

        var TrustManagers = [TrustManager.$new()];
        SSLContext.init.overload(
            "[Ljavax.net.ssl.KeyManager;",
            "[Ljavax.net.ssl.TrustManager;",
            "java.security.SecureRandom"
        ).implementation = function (keyManager, trustManager, secureRandom) {
            console.log("[+] Replacing TrustManager with TrustAllManager");
            SSLContext.init.overload(
                "[Ljavax.net.ssl.KeyManager;",
                "[Ljavax.net.ssl.TrustManager;",
                "java.security.SecureRandom"
            ).call(this, keyManager, TrustManagers, secureRandom);
        };
    } catch (e) {
        console.log("[-] SSLContext hook failed: " + e);
    }

    // --- HostnameVerifier (accept all) ---
    try {
        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");

        var Verifier = Java.registerClass({
            name: "com.frida.AllowAllHostnameVerifier",
            implements: [HostnameVerifier],
            methods: {
                verify: function (hostname, session) {
                    console.log("[+] Bypassing HostnameVerifier: " + hostname);
                    return true;
                }
            }
        });

        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (verifier) {
            HttpsURLConnection.setDefaultHostnameVerifier.call(Verifier.$new());
        };
    } catch (e) {
        console.log("[-] HostnameVerifier hook failed: " + e);
    }

    console.log("[*] SSL pinning bypass loaded.");
});
```

---

## Usage

```bash
# Attach to running app
frida -U -f com.example.app -l script.js --no-pause

# Or attach to already-running process
frida -U com.example.app -l script.js
```

| Flag | Meaning |
|------|---------|
| `-U` | USB device |
| `-f` | Spawn app |
| `-l` | Load script |
| `--no-pause` | Don't pause after spawn |

> **Note:** These are standard tools used in authorized penetration testing, bug bounty research, and security analysis of applications you own or have permission to test.