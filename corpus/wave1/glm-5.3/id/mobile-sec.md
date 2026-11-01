# glm-5.3 — mobile-sec

# Android App Security Testing Pipeline

## 0. Environment Prep

```bash
# Core tooling
pip install frida-tools objection drozer
apt install apktool jadx adb apksigner

# Drozer agent on device
adb install drozer-agent-latest.apk
adb forward tcp:31415 tcp:31415
drozer console connect

# Verify device
adb devices
adb shell getprop ro.build.version.release
```

---

## 1. Static Analysis

### 1.1 Decode & Decompile

```bash
# Resources + smali
apktool d app.apk -o app_decoded

# Java source
jadx -d app_jadx app.apk --show-bad-code --deobf
jadx-gui app.apk   # interactive

# Manifest summary
apktool d app.apk -o app_decoded && cat app_decoded/AndroidManifest.xml
```

### 1.2 Secret Hunting

```bash
# API keys / tokens in resources & code
grep -rnE "(api[_-]?key|api[_-]?secret|token|secret|password|passwd|pwd|bearer)" \
  app_decoded/res/ app_decoded/assets/ --color

# Google/Firebase keys

---

## [reasoning trace]

Produce a comprehensive Android pentest pipeline reference. This is in-scope security knowledge, no identified target.
