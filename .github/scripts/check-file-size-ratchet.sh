#!/usr/bin/env bash
# Fail if oversized files grow past their baseline, or if a new file exceeds
# the hard limit for new sources (see CONTRIBUTING.md).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
baseline_path="${FILE_SIZE_BASELINE:-$root/.github/guardrails/file-size-baseline.json}"
export PYTHONPATH="$root/.github/scripts${PYTHONPATH:+:$PYTHONPATH}"

if [[ ! -f "$baseline_path" ]]; then
  echo "::error::missing file-size baseline at $baseline_path"
  exit 1
fi

python3 - "$baseline_path" "$root" <<'PY'
import json, sys
from pathlib import Path
from lib.surfaces import hard_new_limit, soft_limit

baseline_path = Path(sys.argv[1])
root = Path(sys.argv[2])
data = json.loads(baseline_path.read_text())
soft = soft_limit(data)
hard_new = hard_new_limit(data)
known = {entry["path"]: int(entry["lines"]) for entry in data["files"]}

failed = 0
grown = []
new_oversized = []
missing = []

for rel, baseline_lines in sorted(known.items()):
    path = root / rel
    if not path.is_file():
        missing.append(rel)
        continue
    lines = sum(1 for _ in path.open("rb"))
    if lines > baseline_lines:
        grown.append((rel, baseline_lines, lines))

for path in sorted((root / "crates").rglob("*.rs")):
    if "target" in path.parts:
        continue
    rel = str(path.relative_to(root))
    if rel in known:
        continue
    lines = sum(1 for _ in path.open("rb"))
    if lines > hard_new:
        new_oversized.append((rel, lines, hard_new))
    elif lines > soft:
        print(f"::warning file={rel}::{rel} is {lines} lines (soft limit {soft}); prefer splitting before it hits {hard_new}")

if missing:
    print("::error::baseline entries missing on disk (update baseline if intentional removals/renames):")
    for rel in missing:
        print(f"  - {rel}")
    failed = 1

if grown:
    print("::error::oversized files grew past their ratchet baseline:")
    for rel, before, after in grown:
        print(f"  - {rel}: {before} -> {after} (+{after - before})")
        print("    Split the file or bump the baseline with justification in the PR.")
    failed = 1

if new_oversized:
    print("::error::new files exceed the hard size limit for new sources:")
    for rel, lines, limit in new_oversized:
        print(f"  - {rel}: {lines} lines (limit {limit})")
    failed = 1

if failed:
    sys.exit(1)

print(f"file-size ratchet ok ({len(known)} baselined files, soft={soft}, hard_new={hard_new})")
PY
