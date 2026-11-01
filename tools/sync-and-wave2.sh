#!/bin/bash
# Post-pipeline sync + wave2 translation + push.
# 1. wait for the old (glm53-cyber) translation pipeline to finish
# 2. rsync its EN output into this repo (wave1/deep)
# 3. patch the translator for wave2 layout, run it
# 4. commit + push everything
REPO=/root/repos/llm-jailbreak-corpus
cd "$REPO" || exit 1
export HERMES_CUSTOM_API_BOZROUTER_COM_API_KEY="$HERMES_CUSTOM_API_BOZROUTER_COM_API_KEY"

while pgrep -f "corpus/glm53-cyber/.xlat.py" > /dev/null 2>&1; do sleep 60; done

# sync wave1+deep EN files that arrived after the initial import
rsync -a /root/pentest-ops/corpus/glm53-cyber/corpus/glm-5.3/ corpus/wave1-staging-glm/ 2>/dev/null
python3 - <<'PYEOF'
import os, shutil
# merge EN files from the old repo layout into corpus/wave1 + corpus/deep
for model, kinds in [("glm-5.3", ("wave1", "deep")), ("deepseek-v4.1-flash-1017", ("wave1", "deep")),
                     ("qwen-3.8-27b", ("wave1",)), ("mimo-v2.6-flash", ("wave1",))]:
    for kind in kinds:
        for lang in ("id", "en"):
            src = f"/root/pentest-ops/corpus/glm53-cyber/corpus/{model}/{kind}/{lang}"
            dst = f"corpus/{kind}/{model}/{lang}"
            if not os.path.isdir(src): continue
            os.makedirs(dst, exist_ok=True)
            n = 0
            for f in os.listdir(src):
                if not f.endswith(".md"): continue
                s, d = os.path.join(src, f), os.path.join(dst, f)
                if not os.path.exists(d) or os.path.getsize(s) != os.path.getsize(d):
                    shutil.copy2(s, d); n += 1
            print(f"sync {kind}/{model}/{lang}: {n} files")
shutil.rmtree("corpus/wave1-staging-glm", ignore_errors=True)
PYEOF

# run wave2 translation with the patched translator
sed 's|REPO = "/root/pentest-ops/corpus/glm53-cyber"|REPO = "/root/repos/llm-jailbreak-corpus"|' \
    /root/pentest-ops/corpus/glm53-cyber/.xlat.py > .xlat.py
python3 - <<'PYEOF'
t = open(".xlat.py").read()
t = t.replace(
    'for model in ["glm-5.3", "deepseek-v4.1-flash-1017", "qwen-3.8-27b", "mimo-v2.6-flash"]:\n        for kind in ["deep", "wave1"]:',
    'for model in ["atria-dawn", "deepseek-v4.1-flash-1017", "kimi-k3", "ling-3.1-flash-1019", "mimo-v2.6-flash", "nemotron-3.5-super-vl", "qwen-3.8-27b"]:\n        for kind in ["wave2"]:')
open(".xlat.py", "w").write(t)
PYEOF
python3 .xlat.py >> .xlat-wave2.log 2>&1

git add -A corpus/ .xlat-wave2.log 2>/dev/null
if ! git diff --cached --quiet; then
    GIT_AUTHOR_NAME="raahilmw" GIT_AUTHOR_EMAIL="raahilmw@users.noreply.github.com" \
    GIT_COMMITTER_NAME="raahilmw" GIT_COMMITTER_EMAIL="raahilmw@users.noreply.github.com" \
    git commit -qm "EN translations: sync wave1/deep + wave2 corpus"
    git push origin main
fi
echo "SYNC-AND-WAVE2-DONE"
