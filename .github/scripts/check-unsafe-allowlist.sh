#!/usr/bin/env bash
# Fail if production crates lack a crate-level unsafe policy, or if `unsafe`
# appears outside modules that explicitly allow it.
#
# Prefer compiler enforcement:
#   #![forbid(unsafe_code)]  — crates with no unsafe
#   #![deny(unsafe_code)] + #[allow(unsafe_code)] on specific modules — rare exceptions
#   #![allow(unsafe_code)]   — FFI boundary crate only
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
failed=0

# Discover production crate roots (exclude experimental trees).
mapfile -t production_libs < <(
  find "$root/crates" -mindepth 3 -maxdepth 3 -type f -path '*/src/lib.rs' \
    ! -path '*/experimental/*' | sort | while read -r path; do
      printf '%s\n' "${path#"$root"/}"
    done
)

if ((${#production_libs[@]} == 0)); then
  echo "::error::no production crate roots discovered under crates/*/src/lib.rs"
  exit 1
fi

for lib in "${production_libs[@]}"; do
  path="$root/$lib"
  if [[ ! -f "$path" ]]; then
    echo "::error::missing $lib"
    failed=1
    continue
  fi
  if ! grep -qE '#!\[(forbid|deny|allow)\(unsafe_code\)\]' "$path"; then
    echo "::error file=$lib::$lib must declare #![forbid|deny|allow(unsafe_code)]"
    failed=1
  fi
done

# Textual fallback only for files that do not inherit an allow(unsafe_code) path.
# Strip line comments and simple block comments before matching to avoid doc hits.
python3 - "$root" <<'PY' || failed=1
import re, sys
from pathlib import Path

root = Path(sys.argv[1])
# Modules explicitly allowed to contain unsafe (must match crate attributes).
allowed = {
    "crates/common/src/secret_felt.rs",
    # Entire FFI crate is the raw-pointer boundary.
}
for path in (root / "crates/ffi/src").rglob("*.rs"):
    allowed.add(str(path.relative_to(root)))

comment_line = re.compile(r"//.*?$", re.M)
block_comment = re.compile(r"/\*.*?\*/", re.S)
string_lit = re.compile(r'"(?:\\.|[^"\\])*"')

failed = 0
for path in sorted((root / "crates").rglob("*.rs")):
    if "target" in path.parts or "experimental" in path.parts:
        continue
    rel = str(path.relative_to(root))
    if rel in allowed:
        continue
    # Skip crate roots that allow unsafe at the crate level (ffi handled above).
    text = path.read_text(encoding="utf-8", errors="ignore")
    stripped = block_comment.sub("", text)
    stripped = comment_line.sub("", stripped)
    stripped = string_lit.sub('""', stripped)
    if re.search(r"\bunsafe\b", stripped):
        print(f"::error file={rel}::{rel} contains `unsafe` outside an allowlisted module")
        for i, line in enumerate(stripped.splitlines(), 1):
            if re.search(r"\bunsafe\b", line):
                print(f"  {rel}:{i}:{line.strip()}")
                break
        failed = 1

sys.exit(failed)
PY

if (( failed == 1 )); then
  exit 1
fi
echo "unsafe policy ok"
