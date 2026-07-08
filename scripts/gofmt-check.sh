#!/bin/bash
# Check gofmt on changed Go files when a base ref is provided; otherwise check all Go files.

set -euo pipefail

base_ref=${GOFMT_BASE_REF:-}
files=()

if [ -n "$base_ref" ] && git rev-parse --verify --quiet "$base_ref^{commit}" >/dev/null; then
    while IFS= read -r file; do
        files+=("$file")
    done < <(git diff --name-only --diff-filter=ACMR "$base_ref"...HEAD -- '*.go')
else
    while IFS= read -r file; do
        files+=("$file")
    done < <(find . -name '*.go' -not -path './.git/*')
fi

if [ "${#files[@]}" -eq 0 ]; then
    echo "No Go files to check with gofmt."
    exit 0
fi

unformatted=$(gofmt -l "${files[@]}")
if [ -n "$unformatted" ]; then
    echo "gofmt required for:"
    echo "$unformatted"
    exit 1
fi

echo "gofmt ok for ${#files[@]} file(s)."
