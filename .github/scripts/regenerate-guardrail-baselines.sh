#!/usr/bin/env bash
# Regenerate committed guardrail baselines after intentional surface changes.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
export PYTHONPATH="$root/.github/scripts${PYTHONPATH:+:$PYTHONPATH}"

python3 - <<'PY'
import hashlib
import json
import shutil
from pathlib import Path

from lib.surfaces import (
    extract_wasm_exports,
    hard_new_limit,
    load_baseline,
    oversized_rust_files,
    soft_limit,
)

root = Path(".")
existing = load_baseline()
soft = soft_limit(existing)
hard_new = hard_new_limit(existing)

rows = oversized_rust_files(root, min_lines=soft)
baseline = {
    "version": 1,
    "soft_limit": soft,
    "hard_limit_new_files": hard_new,
    "notes": "Baseline of existing oversized files. CI fails if any listed file grows, or if a new file exceeds hard_limit_new_files.",
    "files": rows,
}
path = root / ".github/guardrails/file-size-baseline.json"
path.write_text(json.dumps(baseline, indent=2) + "\n")
print(f"updated {path} ({len(rows)} files, soft_limit={soft})")

# FFI snapshot only (digest is derived at check time).
hdr = root / "packages/kms-c/include/kms.h"
shutil.copy(hdr, root / ".github/guardrails/ffi-kms.h.snapshot")
digest = hashlib.sha256(hdr.read_bytes()).hexdigest()
print(f"updated FFI snapshot ({digest})")

exports = extract_wasm_exports(root)
(root / ".github/guardrails/wasm-exports.txt").write_text("\n".join(exports) + "\n")
print(f"updated wasm exports ({len(exports)} entries)")
PY

echo "Baselines regenerated. Review the diff before committing."
echo "Note: file-size baseline bumps require a docs/design/ note."
