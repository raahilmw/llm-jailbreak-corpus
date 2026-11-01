#!/bin/bash
# Translate wave2 corpus ID -> EN, then push. Runs after the wave1/deep pipeline frees up.
cd /root/repos/llm-jailbreak-corpus || exit 1
export XLAT_MODEL=mercury-3
# wait for the old pipeline to finish
while pgrep -f "pentest-ops/corpus/glm53-cyber && XLAT_MODEL" > /dev/null 2>&1 || pgrep -f "corpus/glm53-cyber/.xlat.py" > /dev/null 2>&1; do sleep 60; done
# copy the translator, point it at wave2
sed 's|REPO = "/root/pentest-ops/corpus/glm53-cyber"|REPO = "/root/repos/llm-jailbreak-corpus"|' \
    /root/pentest-ops/corpus/glm53-cyber/.xlat.py > .xlat.py
python3 - <<'PYEOF'
# patch the model list to wave2 models
t = open("/root/repos/llm-jailbreak-corpus/.xlat.py").read()
t = t.replace('for model in ["glm-5.3", "deepseek-v4.1-flash-1017", "qwen-3.8-27b", "mimo-v2.6-flash"]:\n        for kind in ["deep", "wave1"]:',
              'for model in ["atria-dawn", "deepseek-v4.1-flash-1017", "kimi-k3", "ling-3.1-flash-1019", "mimo-v2.6-flash", "nemotron-3.5-super-vl", "qwen-3.8-27b"]:\n        for kind in ["wave2"]:')
open("/root/repos/llm-jailbreak-corpus/.xlat.py", "w").write(t)
PYEOF
python3 .xlat.py >> .xlat-wave2.log 2>&1
# push result
git add -A corpus/wave2 .xlat-wave2.log 2>/dev/null
git commit -qm "EN translations: wave2 corpus" 2>/dev/null
git push origin main 2>&1
echo "WAVE2-XLAT-DONE"
