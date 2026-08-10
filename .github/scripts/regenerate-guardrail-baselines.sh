#!/usr/bin/env bash
# Regenerate committed guardrail baselines after intentional surface changes.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

python3 - <<'PY'
import hashlib, json, re, shutil
from pathlib import Path

root = Path(".")

# File-size baseline
rows = []
for path in sorted((root / "crates").rglob("*.rs")):
    if "target" in path.parts:
        continue
    n = sum(1 for _ in path.open("rb"))
    if n >= 350:
        rows.append({"path": str(path.relative_to(root)), "lines": n})
baseline = {
    "version": 1,
    "soft_limit": 350,
    "hard_limit_new_files": 500,
    "notes": "Baseline of existing oversized files. CI fails if any listed file grows, or if a new file exceeds hard_limit_new_files.",
    "files": rows,
}
path = root / ".github/guardrails/file-size-baseline.json"
path.write_text(json.dumps(baseline, indent=2) + "\n")
print(f"updated {path} ({len(rows)} files)")

# Unsafe allowlist
unsafe_files = []
for path in sorted((root / "crates").rglob("*.rs")):
    if "target" in path.parts:
        continue
    if re.search(r"\bunsafe\b", path.read_text(errors="ignore")):
        unsafe_files.append(str(path.relative_to(root)))
allow = root / ".github/guardrails/unsafe-allowlist.txt"
allow.write_text(
    "# Files allowed to contain `unsafe`. Adding a new file requires a design note.\n"
    + "\n".join(unsafe_files)
    + "\n"
)
print(f"updated {allow} ({len(unsafe_files)} files)")

# FFI snapshot
hdr = root / "packages/kms-c/include/kms.h"
digest = hashlib.sha256(hdr.read_bytes()).hexdigest()
(root / ".github/guardrails/ffi-kms.h.sha256").write_text(
    f"{digest}  packages/kms-c/include/kms.h\n"
)
shutil.copy(hdr, root / ".github/guardrails/ffi-kms.h.snapshot")
print(f"updated FFI snapshot ({digest})")

# WASM exports
exports = []
for path in sorted((root / "crates/wasm/src").rglob("*.rs")):
    lines = path.read_text().splitlines()
    i = 0
    while i < len(lines):
        if "#[wasm_bindgen" in lines[i] and "wasm_bindgen_test" not in lines[i]:
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
(root / ".github/guardrails/wasm-exports.txt").write_text("\n".join(exports) + "\n")
print(f"updated wasm exports ({len(exports)} entries)")
PY

echo "Baselines regenerated. Review the diff before committing."
