#!/usr/bin/env bash
set -euo pipefail

lab_root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$lab_root"

required=(
    Dockerfile
    compose.yaml
    lab
    poc/cxl_mailbox_rce.py
    scripts/make-profile.py
    scripts/run-lab.sh
    tools/cxl-layout-probe.c
)
for path in "${required[@]}"; do
    if [[ ! -f "$path" ]]; then
        echo "missing required lab file: $path" >&2
        exit 2
    fi
done

bash -n lab scripts/run-lab.sh scripts/verify.sh
python3 -B -c 'import ast, pathlib; [ast.parse(pathlib.Path(p).read_text(), filename=p) for p in ("scripts/make-profile.py", "poc/cxl_mailbox_rce.py")]'

if [[ -d tests ]]; then
    PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p 'test_*.py' -v
fi

rg -q '562bae590f194fb590beb5c65da44fc35ab9f64a' Dockerfile compose.yaml scripts/run-lab.sh
rg -q '^\s*network_mode:\s*none\s*$' compose.yaml
rg -q '^\s*read_only:\s*true\s*$' compose.yaml
rg -q '^\s*-\s*ALL\s*$' compose.yaml
rg -q 'no-new-privileges:true' compose.yaml
rg -q 'refusing to run: the reproduction is permitted only inside its lab container' scripts/run-lab.sh

local_home_pattern='/'"Users"'/'
if rg -n --hidden \
    --glob '!artifacts/**' \
    --glob '!.git/**' \
    "(192\\.168\\.1\\.119|${local_home_pattern}[^ ]+|root@([0-9]{1,3}\\.){3}[0-9]{1,3}|gh[pousr]_[A-Za-z0-9_]{20,})" .; then
    echo "local target/path or credential-shaped data found" >&2
    exit 3
fi

if command -v shellcheck >/dev/null 2>&1; then
    shellcheck lab scripts/run-lab.sh scripts/verify.sh
fi
if command -v gitleaks >/dev/null 2>&1; then
    gitleaks detect --no-git --source . --max-target-megabytes 1 \
        --redact --exit-code 1
fi
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    LAB_RUN_LABEL=run-config-check docker compose \
        --project-directory "$lab_root" \
        -f "$lab_root/compose.yaml" config --quiet
fi

echo "Static lab verification passed."
