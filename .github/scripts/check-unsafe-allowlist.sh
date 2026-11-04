#!/usr/bin/env bash
# Fail if production crates lack a crate-level unsafe policy, if any crate root
# other than the FFI boundary allows unsafe at the crate level, or if `unsafe`
# appears outside modules that explicitly allow it.
#
# Prefer compiler enforcement:
#   #![forbid(unsafe_code)]  — crates with no unsafe
#   #![deny(unsafe_code)] + #[allow(unsafe_code)] on specific modules — rare exceptions
#   #![allow(unsafe_code)]   — crates/ffi/src/lib.rs only
#
# The textual scan is a backstop for the compiler policy. It tokenises each
# file with the shared Rust scanner (comments, strings, raw strings and char
# literals are tracked across lines) instead of stripping them with regexes,
# which a `'"'` char literal or a `"/*"` string literal could defeat.
#
# Usage: check-unsafe-allowlist.sh [repository-root]
set -euo pipefail

scripts_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="${1:-$(cd "$scripts_dir/../.." && pwd)}"

python3 - "$root" "$scripts_dir" <<'PY'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
sys.path.insert(0, sys.argv[2])
from lib.rust_scanner import RustBraceScanner  # noqa: E402

FFI_ROOT = "crates/ffi/src/lib.rs"
# Modules explicitly allowed to contain unsafe (must match crate attributes).
ALLOWED_MODULES = {"crates/common/src/secret_felt.rs"}
POLICY_ATTR = re.compile(r"#!\[(forbid|deny|allow)\(unsafe_code\)\]")
UNSAFE = re.compile(r"\bunsafe\b")


def code_lines(path: Path):
    """Yield (line_number, code_only_text) with comments and literals blanked."""
    scanner = RustBraceScanner()
    text = path.read_text(encoding="utf-8", errors="ignore")
    for number, line in enumerate(text.splitlines(), 1):
        yield number, scanner.strip_line(line)


def production_crate_roots():
    roots = []
    for path in sorted(root.glob("crates/*/src/lib.rs")):
        rel = path.relative_to(root).as_posix()
        if "/experimental/" in f"/{rel}":
            continue
        roots.append(rel)
    return roots


def check_crate_root(rel: str) -> bool:
    policies = set()
    for _, code in code_lines(root / rel):
        policies.update(match.group(1) for match in POLICY_ATTR.finditer(code))
    if not policies:
        print(f"::error file={rel}::{rel} must declare #![forbid|deny(unsafe_code)]")
        return False
    if "allow" in policies and rel != FFI_ROOT:
        print(
            f"::error file={rel}::{rel} allows unsafe at the crate level; "
            f"only {FFI_ROOT} may (use #![deny(unsafe_code)] with a module allowlist)"
        )
        return False
    return True


def is_allowlisted(rel: str) -> bool:
    return rel in ALLOWED_MODULES or rel.startswith("crates/ffi/src/")


def check_unsafe_free(rel: str) -> bool:
    for number, code in code_lines(root / rel):
        if UNSAFE.search(code):
            print(f"::error file={rel},line={number}::{rel} contains `unsafe` outside an allowlisted module")
            print(f"  {rel}:{number}:{code.strip()}")
            return False
    return True


roots = production_crate_roots()
if not roots:
    print("::error::no production crate roots discovered under crates/*/src/lib.rs")
    sys.exit(1)

ok = all([check_crate_root(rel) for rel in roots])
for path in sorted(root.glob("crates/**/*.rs")):
    parts = path.relative_to(root).parts
    if "target" in parts or "experimental" in parts:
        continue
    rel = path.relative_to(root).as_posix()
    if is_allowlisted(rel):
        continue
    ok = check_unsafe_free(rel) and ok

sys.exit(0 if ok else 1)
PY

echo "unsafe policy ok"
