#!/usr/bin/env bash
# Freeze the canonical C ABI header surface.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
header="$root/packages/kms-c/include/kms.h"
snapshot="$root/.github/guardrails/ffi-kms.h.snapshot"

if [[ ! -f "$header" ]]; then
  echo "::error::missing $header"
  exit 1
fi
if [[ ! -f "$snapshot" ]]; then
  echo "::error::missing FFI surface snapshot at $snapshot"
  exit 1
fi

failed=0
if ! cmp -s "$header" "$snapshot"; then
  echo "::error::packages/kms-c/include/kms.h differs from .github/guardrails/ffi-kms.h.snapshot"
  diff -u "$snapshot" "$header" | head -n 80 || true
  failed=1
fi

jvm_header="$root/packages/kms-jvm/src/main/c/kms.h"
if [[ -f "$jvm_header" ]] && ! cmp -s "$header" "$jvm_header"; then
  echo "::error::$jvm_header differs from packages/kms-c/include/kms.h"
  failed=1
fi

swift_header="$root/packages/kms-swift/Sources/CKms/include/kms.h"
if [[ -f "$swift_header" ]]; then
  if ! python3 - "$header" "$swift_header" <<'PY'
import sys
from pathlib import Path

SWIFT_ONLY = {
    "void kms_secure_wipe(void *ptr, size_t len);",
}


def significant_lines(text: str) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("/*") or line.startswith("//") or line.startswith("*"):
            continue
        if line.endswith("*/") and not line.startswith("#"):
            continue
        lines.append(line)
    return lines


canonical = significant_lines(Path(sys.argv[1]).read_text())
swift = [line for line in significant_lines(Path(sys.argv[2]).read_text()) if line not in SWIFT_ONLY]

if canonical != swift:
    # Prefer an ordered diff so field reorder is visible.
    import difflib

    for line in difflib.unified_diff(
        canonical, swift, fromfile="kms-c/include/kms.h", tofile="kms-swift/.../kms.h", lineterm=""
    ):
        print(f"::error::{line}")
    sys.exit(1)

print("Swift header ABI matches canonical surface (plus Swift-only helpers)")
PY
  then
    failed=1
  fi
fi

if ! python3 - <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, str(Path(".github/scripts").resolve()))
from lib.surfaces import compare_ffi_surfaces, extract_rust_ffi_functions

errors = compare_ffi_surfaces()
if errors:
    for err in errors:
        print(f"::error::{err}")
    sys.exit(1)
count = len(extract_rust_ffi_functions())
print(
    f"Rust/Dart/JVM FFI bindings match packages/kms-c/include/kms.h ({count} functions)"
)
PY
then
  failed=1
fi

if (( failed == 1 )); then
  echo "If the ABI change is intentional, update the snapshot/headers and include a design note."
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  digest="$(sha256sum "$header" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  digest="$(shasum -a 256 "$header" | awk '{print $1}')"
else
  digest="(unavailable)"
fi
echo "FFI surface snapshot ok ($digest)"
