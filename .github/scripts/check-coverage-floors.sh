#!/usr/bin/env bash
# Generate the client coverage report, then enforce committed scoped floors.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
report_dir="$(mktemp -d)"
report_path="$report_dir/client.json"

cd "$root"
cargo llvm-cov -p krusty-kms-client --lib --locked --json --summary-only --output-path "$report_path"
python3 .github/scripts/check-coverage-floors.py --report "$report_path" --floors .github/guardrails/coverage-floors.json --root "$root"
