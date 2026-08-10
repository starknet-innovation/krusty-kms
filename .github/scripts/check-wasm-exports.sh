#!/usr/bin/env bash
# Freeze the wasm-bindgen export surface (js_name / signatures).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
snapshot="$root/.github/guardrails/wasm-exports.txt"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
export PYTHONPATH="$root/.github/scripts${PYTHONPATH:+:$PYTHONPATH}"

python3 - "$root" "$tmp" <<'PY'
from pathlib import Path
import sys
from lib.surfaces import extract_wasm_exports

root = Path(sys.argv[1])
out = Path(sys.argv[2])
exports = extract_wasm_exports(root)
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
