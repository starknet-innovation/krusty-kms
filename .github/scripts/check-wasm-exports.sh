#!/usr/bin/env bash
# Freeze the wasm-bindgen export surface (js_name / signatures).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
snapshot="$root/.github/guardrails/wasm-exports.txt"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

python3 - "$root" "$tmp" <<'PY'
import re
from pathlib import Path
import sys

root = Path(sys.argv[1])
out = Path(sys.argv[2])
exports = []
for path in sorted((root / "crates/wasm/src").rglob("*.rs")):
    lines = path.read_text().splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if "#[wasm_bindgen" in line and "wasm_bindgen_test" not in line:
            j = i
            while j < len(lines) and not re.match(
                r"^\s*(pub\s+)?(async\s+)?(unsafe\s+)?(fn|struct|enum|type|const|static)\b",
                lines[j],
            ) and not re.match(r"^\s*impl\b", lines[j]):
                j += 1
            if j < len(lines):
                attrs = "\n".join(lines[i : j + 1])
                m = re.search(r'js_name\s*=\s*"([^"]+)"', attrs)
                name = m.group(1) if m else lines[j].strip()
                exports.append(f"{path.relative_to(root)}: {name}")
            i = j + 1
        else:
            i += 1
out.write_text("\n".join(exports) + ("\n" if exports else ""))
PY

if [[ ! -f "$snapshot" ]]; then
  echo "::error::missing wasm export snapshot at $snapshot"
  exit 1
fi

if ! cmp -s "$tmp" "$snapshot"; then
  echo "::error::WASM export surface changed versus .github/guardrails/wasm-exports.txt"
  diff -u "$snapshot" "$tmp" | head -n 120 || true
  echo "If intentional, update the snapshot and include a design note / ## Design section."
  exit 1
fi

echo "WASM export surface ok ($(wc -l < "$snapshot") entries)"
