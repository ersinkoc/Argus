#!/bin/bash
# Enforce coarse package-layer dependency guardrails for production Go files.

set -euo pipefail

python3 - <<'PY'
import ast
import pathlib
import re
import sys

MODULE_PREFIX = "github.com/ersinkoc/argus/internal/"

# Production packages below these layers must not depend on application-facing
# orchestration packages. Keep this list conservative so it catches coupling
# regressions without blocking existing lower-layer relationships.
FORBIDDEN_IMPORTS = {
    "admin": {"core", "gateway"},
    "audit": {"admin", "core", "gateway"},
    "auth": {"admin", "core", "gateway"},
    "classify": {"admin", "core", "gateway"},
    "cluster": {"admin", "core", "gateway"},
    "config": {"admin", "core", "gateway"},
    "inspection": {"admin", "core", "gateway"},
    "masking": {"admin", "core", "gateway"},
    "metrics": {"admin", "core", "gateway"},
    "plan": {"admin", "core", "gateway"},
    "plugin": {"admin", "core", "gateway"},
    "policy": {"admin", "core", "gateway"},
    "pool": {"admin", "core", "gateway"},
    "protocol": {"admin", "core", "gateway"},
    "ratelimit": {"admin", "core", "gateway"},
    "session": {"admin", "core", "gateway"},
}

import_re = re.compile(r'^\s*(?:[\w.]+\s+)?"([^"]+)"')
violations = []

for path in sorted(pathlib.Path("internal").rglob("*.go")):
    if path.name.endswith("_test.go"):
        continue

    parts = path.parts
    if len(parts) < 3:
        continue
    source_package = parts[1]
    forbidden = FORBIDDEN_IMPORTS.get(source_package, set())
    if not forbidden:
        continue

    in_import_block = False
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if stripped == "import (":
            in_import_block = True
            continue
        if in_import_block and stripped == ")":
            in_import_block = False
            continue
        if stripped.startswith("import "):
            import_path = stripped.removeprefix("import ").strip()
            try:
                value = ast.literal_eval(import_path.split()[-1])
            except (SyntaxError, ValueError):
                continue
        elif in_import_block:
            match = import_re.match(line)
            if not match:
                continue
            value = match.group(1)
        else:
            continue

        if not value.startswith(MODULE_PREFIX):
            continue
        target = value.removeprefix(MODULE_PREFIX).split("/", 1)[0]
        if target in forbidden:
            violations.append(f"{path}:{line_number}: internal/{source_package} must not import internal/{target} ({value})")

if violations:
    print("Forbidden internal package dependencies found:")
    print("\n".join(violations))
    sys.exit(1)

print("internal package dependency guardrails ok")
PY
