#!/usr/bin/env bash
# Freeze the canonical C ABI header surface.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
header="$root/packages/kms-c/include/kms.h"
snapshot="$root/.github/guardrails/ffi-kms.h.snapshot"
digest_file="$root/.github/guardrails/ffi-kms.h.sha256"

if [[ ! -f "$header" ]]; then
  echo "::error::missing $header"
  exit 1
fi
if [[ ! -f "$snapshot" || ! -f "$digest_file" ]]; then
  echo "::error::missing FFI surface snapshot under .github/guardrails/"
  exit 1
fi

actual_digest="$(sha256sum "$header" | awk '{print $1}')"
expected_digest="$(awk '{print $1}' "$digest_file")"

failed=0
if [[ "$actual_digest" != "$expected_digest" ]]; then
  echo "::error::packages/kms-c/include/kms.h digest mismatch"
  echo "  expected: $expected_digest"
  echo "  actual:   $actual_digest"
  failed=1
fi

if ! cmp -s "$header" "$snapshot"; then
  echo "::error::packages/kms-c/include/kms.h differs from .github/guardrails/ffi-kms.h.snapshot"
  diff -u "$snapshot" "$header" | head -n 80 || true
  failed=1
fi

# JVM ships a copy of the canonical header and must match exactly.
jvm_header="$root/packages/kms-jvm/src/main/c/kms.h"
if [[ -f "$jvm_header" ]] && ! cmp -s "$header" "$jvm_header"; then
  echo "::error::$jvm_header differs from packages/kms-c/include/kms.h"
  failed=1
fi

# Swift may append binding-only helpers after the shared ABI. Require the
# canonical header lines to appear in order as a subset.
swift_header="$root/packages/kms-swift/Sources/CKms/include/kms.h"
if [[ -f "$swift_header" ]]; then
  if ! python3 - "$header" "$swift_header" <<'PY'
import sys
from pathlib import Path

canonical = Path(sys.argv[1]).read_text()
swift = Path(sys.argv[2]).read_text()
canon_lines = [ln for ln in canonical.splitlines() if ln.strip()]
swift_lines = swift.splitlines()
si = 0
for line in canon_lines:
    while si < len(swift_lines) and swift_lines[si] != line:
        si += 1
    if si >= len(swift_lines):
        print(f"::error::Swift kms.h is missing canonical ABI line: {line}")
        sys.exit(1)
    si += 1
print("Swift header contains canonical ABI as ordered subset")
PY
  then
    failed=1
  fi
fi

if (( failed == 1 )); then
  echo "If the ABI change is intentional, update the snapshot + digest and include a design note."
  exit 1
fi

echo "FFI surface snapshot ok ($actual_digest)"
