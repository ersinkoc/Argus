#!/bin/bash
# Run Go tests with JSON output and print the slowest packages.

set -o pipefail

OUT=${TEST_TIMING_JSON:-test-timing.jsonl}
TOP_N=${TEST_TIMING_TOP_N:-10}
PACKAGES=${TEST_TIMING_PACKAGES:-./...}

rm -f "$OUT"
read -r -a package_args <<< "$PACKAGES"

echo "Running go test with package timing diagnostics..."
echo "Packages: $PACKAGES"
echo "JSON output: $OUT"

go test -json "${package_args[@]}" -count=1 -timeout 60s 2>&1 | tee "$OUT"
test_status=${PIPESTATUS[0]}

python3 - "$OUT" "$TOP_N" <<'PY'
import json
import sys
from collections import defaultdict

path = sys.argv[1]
top_n = int(sys.argv[2])
packages = {}
seen_actions = defaultdict(set)

with open(path, "r", encoding="utf-8") as handle:
    for line in handle:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        package = event.get("Package")
        action = event.get("Action")
        elapsed = event.get("Elapsed")
        if package:
            seen_actions[package].add(action)
        if package and action in {"pass", "fail"} and isinstance(elapsed, (int, float)):
            packages[package] = max(float(elapsed), packages.get(package, 0.0))

print("")
print("=== Slowest Go test packages ===")
if not packages:
    print("No package elapsed timings found in go test JSON output.")
else:
    for index, (package, elapsed) in enumerate(
        sorted(packages.items(), key=lambda item: item[1], reverse=True)[:top_n],
        start=1,
    ):
        actions = ",".join(sorted(action for action in seen_actions[package] if action))
        print(f"{index:2d}. {elapsed:7.2f}s  {package}  [{actions}]")
PY
summary_status=$?

if [ "$test_status" -ne 0 ]; then
    exit "$test_status"
fi
exit "$summary_status"
