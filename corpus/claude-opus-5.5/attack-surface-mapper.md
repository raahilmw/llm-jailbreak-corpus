```python
#!/usr/bin/env python3
"""Attack-surface mapper: CT subdomains, HTTP fingerprint, JS endpoint extraction,
parameter discovery, JSON report. Stdlib only.

Authorized targets only. Default is passive (CT + public HTTP GET).
Active param discovery (--active) sends probes; use only with explicit permission.
"""
import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

UA = "asm-mapper/1.0 (+authorized-security-testing)"
TIMEOUT = 10
MAX_BODY = 5 * 1024 * 1024

# ---------- HTTP ----------

def http_get(url, want_body=True, max_bytes=MAX_BODY):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            body = b""
            if want_body:
                body = r.read(max_bytes)
            return {
                "url": url,
                "status": r.status,
                "headers": dict(r.headers.items()),
                "body": body,
                "final_url": r.geturl(),
            }
    except urllib.error.HTTPError as e:
        try:
            body = e.read(max_bytes) if want_body else b""
        except Exception:
            body = b""
        return {
            "url": url,
            "status": e.code,
            "headers": dict(e.headers.items()) if e.headers else {},
            "body": body,
            "final_url": url,
        }
    except Exception as e:
        return {"url": url, "error": f"{type(e).__name__}: {e}"}


# ---------- CT subdomain enumeration ----------

def ct_subdomains(domain):
    """Query crt.sh certificate transparency log. Returns sorted set of hostnames."""
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    r = http_get(url)
    if "error" in r or r["status"] != 200:
        return set()
    try:
        data = json.loads(r["body"].decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return set()
    hosts = set()
    suffix = "." + domain.lower()
    for entry in data:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and (name == domain.lower() or name.endswith(suffix)):
                if re.fullmatch(r"[a-z0-9.\-]+", name):
                    hosts.add(name)
    return hosts


# ---------- HTTP fingerprinting ----------

SERVER_PATTERNS = [
    (re.compile(r"nginx/?([\d.]+)?", re.I), "nginx"),
    (re.compile(r"apache/?([\d.]+)?", re.I), "apache"),
    (re.compile(r"microsoft-iis/?([\d.]+)?", re.I), "iis"),
    (re.compile(r"cloudflare", re.I), "cloudflare"),
    (re.compile(r"openresty/?([\d.]+)?", re.I), "openresty"),
    (re.compile(r"gunicorn/?([\d.]+)?", re.I), "gunicorn"),
    (re.compile(r"caddy", re.I), "caddy"),
    (re.compile(r"envoy", re.I), "envoy"),
]

FRAMEWORK_PATTERNS = [
    ("x-powered-by", re.compile(r"express", re.I), "express"),
    ("x-powered-by", re.compile(r"php/?([\d.]+)?", re.I), "php"),
    ("x-powered-by", re.compile(r"asp\.net", re.I), "aspnet"),
    ("x-generator", re.compile(r"drupal", re.I), "drupal"),
    ("x-generator", re.compile(r"wordpress", re.I), "wordpress"),
    ("x-aspnet-version", re.compile(r".+"), "aspnet"),
    ("x-drupal-cache", re.compile(r".+"), "drupal"),
    ("x-shopify-stage", re.compile(r".+"), "shopify"),
    ("x-nextjs-cache", re.compile(r".+"), "nextjs"),
    ("x-vercel-id", re.compile(r".+"), "vercel"),
    ("x-amz-cf-id", re.compile(r".+"), "cloudfront"),
    ("cf-ray", re.compile(r".+"), "cloudflare"),
]

BODY_PATTERNS = [
    (re.compile(r"wp-content|wp-includes", re.I), "wordpress"),
    (re.compile(r"/sites/default/files|drupal-settings", re.I), "drupal"),
    (re.compile(r"__NEXT_DATA__", re.I), "nextjs"),
    (re.compile(r"<meta name=\"generator\" content=\"([^\"]+)\"", re.I), "meta-generator"),
    (re.compile(r"react", re.I), "react-hint"),
    (re.compile(r"vue(\.js)?", re.I), "vue-hint"),
    (re.compile(r"angular", re.I), "angular-hint"),
]

TECH_HEADERS = [
    "server", "x-powered-by", "x-generator", "x-aspnet-version",
    "x-drupal-cache", "x-nextjs-cache", "x-vercel-id", "cf-ray",
    "x-amz-cf-id", "x-shopify-stage", "via", "x-cache",
]

def fingerprint(resp):
    if "error" in resp:
        return {"error": resp["error"]}
    headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
    tech = set()
    server = headers.get("server", "")
    for pat, name in SERVER_PATTERNS:
        if pat.search(server):
            tech.add(name)
    for hname, pat, name in FRAMEWORK_PATTERNS:
        val = headers.get(hname, "")
        if val and pat.search(val):
            tech.add(name)
    body = resp.get("body", b"")
    text = body.decode("utf-8", "replace")[:200_000] if body else ""
    for pat, name in BODY_PATTERNS:
        m = pat.search(text)
        if m:
            if name == "meta-generator":
                tech.add("generator:" + m.group(1).strip())
            else:
                tech.add(name)
    security = {}
    for h in ("strict-transport-security", "content-security-policy",
              "x-frame-options", "x-content-type-options",
              "referrer-policy", "permissions-policy"):
        security[h] = headers.get(h, None)
    return {
        "status": resp.get("status"),
        "final_url": resp.get("final_url"),
        "server": server or None,
        "tech": sorted(tech),
        "headers_of_interest": {k: headers[k] for k in TECH_HEADERS if k in headers},
        "security_headers": security,
        "content_type": headers.get("content-type"),
    }


# ---------- JS bundle endpoint extraction ----------

JS_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+\.js[^"']*)["']""", re.I)
SCRIPT_ANY_RE = re.compile(r"""<script[^>]*>([\s\S]*?)</script>""", re.I)

ENDPOINT_RES = [
    # absolute URLs
    re.compile(r"""["'`](https?://[^\s"'`<>]+)["'`]"""),
    # path-like strings
    re.compile(r"""["'`](/[a-zA-Z0-9_\-./{}$:?=&%]+)["'`]"""),
    # fetch/axios/xhr calls
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|\.open)\s*\(\s*["'`]([^"'`]+)["'`]"""),
    # api-ish
    re.compile(r"""["'`]([a-zA-Z0-9_\-/{}]*/api/[a-zA-Z0-9_\-/{}?=&]+)["'`]"""),
]

def extract_endpoints(text, base_url):
    found = set()
    for pat in ENDPOINT_RES:
        for m in pat.finditer(text):
            val = m.group(1).strip()
            if not val or len(val) > 500:
                continue
            if val.startswith("data:") or val.startswith("javascript:"):
                continue
            if val.startswith("http://") or val.startswith("https://"):
                found.add(val)
            elif val.startswith("/"):
                found.add(urllib.parse.urljoin(base_url, val))
    return found

def find_js_bundles(base_url, max_bundles=50):
    r = http_get(base_url)
    if "error" in r or not r.get("body"):
        return []
    html = r["body"].decode("utf-8", "replace")
    srcs = JS_SRC_RE.findall(html)
    urls = []
    seen = set()
    for s in srcs:
        u = urllib.parse.urljoin(base_url, s)
        if u not in seen:
            seen.add(u)
            urls.append(u)
    return urls[:max_bundles]

def analyze_js(url):
    r = http_get(url, max_bytes=MAX_BODY)
    if "error" in r or not r.get("body"):
        return {"url": url, "error": r.get("error", "no body")}
    text = r["body"].decode("utf-8", "replace")
    eps = extract_endpoints(text, url)
    return {"url": url, "size": len(r["body"]), "endpoints": sorted(eps)}


# ---------- Parameter discovery ----------

PARAM_SOURCES = [
    re.compile(r"""[?&]([a-zA-Z_][a-zA-Z0-9_]{0,30})=["'`]"""),
    re.compile(r"""["'`]([a-zA-Z_][a-zA-Z0-9_]{0,30})["']\s*:\s*["'`]"""),
    re.compile(r"""\bname=["']([a-zA-Z_][a-zA-Z0-9_]{0,30})["']"""),
    re.compile(r"""\b(?:id|name|for)=["']([a-zA-Z_][a-zA-Z0-9_\-]{0,30})["']"""),
]

def discover_params_from_text(text):
    found = set()
    for pat in PARAM_SOURCES:
        for m in pat.finditer(text):
            found.add(m.group(1))
    return found

def active_param_probe(base_url, params):
    """Send benign probes; flag params that change response length/status."""
    if not params:
        return []
    base = http_get(base_url)
    if "error" in base:
        return []
    base_len = len(base.get("body", b""))
    base_status = base.get("status")
    results = []
    for p in sorted(params)[:50]:
        url = base_url + ("&" if "?" in base_url else "?") + urllib.parse.urlencode({p: "asmprobe1"})
        r = http_get(url)
        if "error" in r:
            continue
        rlen = len(r.get("body", b""))
        rstatus = r.get("status")
        if rstatus != base_status or abs(rlen - base_len) > 20:
            results.append({"param": p, "status": rstatus, "len": rlen,
                            "base_status": base_status, "base_len": base_len})
    return results


# ---------- Orchestration ----------

def probe_host(host, scheme="https"):
    url = f"{scheme}://{host}/"
    r = http_get(url)
    if "error" in r and scheme == "https":
        url = f"http://{host}/"
        r = http_get(url)
    fp = fingerprint(r)
    return {"host": host, "url": url, "fingerprint": fp}


def map_host(host, do_active=False):
    entry = probe_host(host)
    base_url = entry["url"]
    if "error" in entry["fingerprint"]:
        return entry
    js_urls = find_js_bundles(base_url)
    js_results = []
    all_endpoints = set()
    all_params = set()
    for ju in js_urls:
        res = analyze_js(ju)
        js_results.append({"url": res["url"], "size": res.get("size"),
                           "endpoint_count": len(res.get("endpoints", [])),
                           "error": res.get("error")})
        for e in res.get("endpoints", []):
            all_endpoints.add(e)
            all_params.update(discover_params_from_text(e))
    # also scan root HTML
    r = http_get(base_url)
    if "error" not in r and r.get("body"):
        html = r["body"].decode("utf-8", "replace")
        all_params.update(discover_params_from_text(html))
        all_endpoints.update(extract_endpoints(html, base_url))
    entry["js_bundles"] = js_results
    entry["endpoints"] = sorted(all_endpoints)
    entry["params"] = sorted(all_params)
    if do_active and all_params:
        entry["active_param_probes"] = active_param_probe(base_url, all_params)
    return entry


def main():
    ap = argparse.ArgumentParser(description="Attack-surface mapper")
    ap.add_argument("domain", help="target domain, e.g. example.com")
    ap.add_argument("-o", "--output", default="asm_report.json")
    ap.add_argument("--active", action="store_true",
                    help="send benign param probes (authorized targets only)")
    ap.add_argument("--max-hosts", type=int, default=50)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    domain = args.domain.strip().lower()
    print(f"[*] CT enumeration for {domain}", file=sys.stderr)
    subs = ct_subdomains(domain)
    subs.add(domain)
    subs = sorted(subs)[: args.max_hosts]
    print(f"[*] {len(subs)} hosts to probe", file=sys.stderr)

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(map_host, h, args.active): h for h in subs}
        for f in as_completed(futs):
            h = futs[f]
            try:
                res = f.result()
            except Exception as e:
                res = {"host": h, "error": f"{type(e).__name__}: {e}"}
            results.append(res)
            print(f"[+] {h}", file=sys.stderr)

    results.sort(key=lambda x: x.get("host", ""))
    report = {
        "target": domain,
        "host_count": len(results),
        "hosts": results,
    }
    with open(args.output, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
    print(f"[*] wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
```

skipped: DNS brute, port scan, auth, rate-limit backoff. Add when CT alone misses internal hosts or target rate-limits crt.sh.

Run: `python3 asm.py example.com -o out.json` (passive). `--active` sends GET probes — authorized targets only.