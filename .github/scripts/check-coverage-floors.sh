#!/usr/bin/env bash
# Generate the client coverage report, then enforce committed scoped floors.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
report_dir="$(mktemp -d)"
report_path="$report_dir/client.json"
base_ref=""

if [[ $# -eq 2 && "$1" == "--base-ref" ]]; then
  base_ref="$2"
elif [[ $# -ne 0 ]]; then
  echo "usage: $0 [--base-ref <git-revision>]" >&2
  exit 2
fi

base_args=()
if [[ -n "$base_ref" ]]; then
  base_args=(--base-ref "$base_ref")
fi

cd "$root"
cargo llvm-cov -p krusty-kms-client --lib --locked --json --summary-only --output-path "$report_path"
python3 .github/scripts/check-coverage-floors.py --report "$report_path" --floors .github/guardrails/coverage-floors.json --root "$root" "${base_args[@]}"
