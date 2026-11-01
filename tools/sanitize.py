#!/usr/bin/env python3
"""Sanitize kimi3 corpus for publishing.

Rewrites/creates files under DEST:
- strips router/gateway names from file headers (bozrouter, 9router, rv/ prefixes)
- keeps per-model COMPLY/REFUSED verdicts intact
- refuses logs kept as data, with router names scrubbed
"""
import os, re, shutil, sys

SRC = "/root/kimi3/corpus"
DEST = "/root/repos/llm-jailbreak-corpus/models"
MODELS = {
    "atria":      "atria-dawn",
    "ds-v41":     "deepseek-v4.1-flash-1017",
    "kimi-k3":    "kimi-k3",
    "ling31":     "ling-3.1-flash-1019",
    "mimo26":     "mimo-v2.6-flash",
    "nemotron35": "nemotron-3.5-super-vl",
    "qwen38":     "qwen-3.8-27b",
}

def scrub(text: str) -> str:
    t = text
    t = t.replace("rv/moonshotai/Kimi-K3", "kimi-k3")
    t = re.sub(r"bozrouter[ \t]*", "", t, flags=re.I)
    t = re.sub(r"\b9router\b", "router", t)
    t = re.sub(r"\brv/", "", t)
    return t

def main():
    total = kept = refused = 0
    for srcmodel, destmodel in MODELS.items():
        srcdir = os.path.join(SRC, srcmodel)
        dstdir = os.path.join(DEST, destmodel)
        os.makedirs(dstdir, exist_ok=True)
        for fn in sorted(os.listdir(srcdir)):
            if not fn.endswith(".md"):
                continue
            srcp = os.path.join(srcdir, fn)
            text = open(srcp, encoding="utf-8").read()
            # skip files that are pure stubs (no content beyond header)
            if text.count("## Answer") == 0 and text.count("## Probe") == 0:
                continue
            out = scrub(text)
            dstfn = fn.replace(".refused.md", ".REFUSED.md")
            dstp = os.path.join(dstdir, dstfn)
            open(dstp, "w", encoding="utf-8").write(out)
            total += 1
            if "refused" in fn.lower():
                refused += 1
            else:
                kept += 1
    print(f"files copied: {total} (comply {kept}, refused {refused})")

if __name__ == "__main__":
    main()
