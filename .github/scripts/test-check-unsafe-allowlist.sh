#!/usr/bin/env bash
# Fixture-based self-tests for check-unsafe-allowlist.sh: the scan must catch
# a plain `unsafe`, the char-literal and string-literal evasions that defeated
# regex stripping (audit 2026-11-04, M-5), and a crate-level allow outside the
# FFI crate, while accepting the allowlisted modules and look-alike text.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
checker="$repo_root/.github/scripts/check-unsafe-allowlist.sh"
fixture_root="$(mktemp -d)"
trap 'rm -rf "$fixture_root"' EXIT

expect_failure() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "self-test failed: $description unexpectedly passed" >&2
    exit 1
  fi
}

expect_success() {
  local description="$1"
  shift
  if ! "$@" >/dev/null 2>&1; then
    echo "self-test failed: $description unexpectedly failed" >&2
    exit 1
  fi
}

# A minimal production tree: the FFI boundary (crate-level allow, unsafe),
# common (deny + module allowlist for secret_felt.rs) and a forbid crate whose
# module file is the subject of each case.
reset_fixture() {
  rm -rf "$fixture_root/crates"
  mkdir -p "$fixture_root/crates/ffi/src" "$fixture_root/crates/common/src" "$fixture_root/crates/kms/src"
  printf '%s\n' '#![allow(unsafe_code)] // raw-pointer C ABI boundary' \
    'pub fn f(p: *const u8) -> u8 { unsafe { *p } }' >"$fixture_root/crates/ffi/src/lib.rs"
  printf '%s\n' '#![deny(unsafe_code)]' 'mod secret_felt;' >"$fixture_root/crates/common/src/lib.rs"
  printf '%s\n' '#[allow(unsafe_code)]' \
    'fn wipe(p: *mut u8) { unsafe { core::ptr::write_volatile(p, 0) } }' \
    >"$fixture_root/crates/common/src/secret_felt.rs"
  printf '%s\n' '#![forbid(unsafe_code)]' 'mod subject;' >"$fixture_root/crates/kms/src/lib.rs"
  printf '%s\n' 'pub fn safe() {}' >"$fixture_root/crates/kms/src/subject.rs"
}

subject="$fixture_root/crates/kms/src/subject.rs"

reset_fixture
expect_success "allowlisted fixture tree" "$checker" "$fixture_root"

# Look-alike text that is not code must pass: doc comments, block comments,
# string, raw-string and char literals, and a `'"'` or `"/*"` literal
# followed by safe code.
reset_fixture
cat >"$subject" <<'RS'
//! This module never uses unsafe code.
/// Doc comment that says unsafe { } for emphasis.
/* unsafe { block comment } */
/* nested /* unsafe */ still a comment */
pub fn safe() -> usize {
    let a = "unsafe { in a string }";
    let b = r#"unsafe { in a raw string "with quotes" }"#;
    let c = '"';
    let d = "/*";
    let e = b'\'';
    let f = "escaped \" quote then unsafe";
    let _lifetime: &'static str = "x";
    a.len() + b.len() + d.len() + f.len() + usize::from(c == '"') + usize::from(e == b'\'')
}
RS
expect_success "look-alike text in comments and literals" "$checker" "$fixture_root"

reset_fixture
printf '%s\n' 'pub fn f(p: *const u8) -> u8 { unsafe { *p } }' >"$subject"
expect_failure "plain unsafe block" "$checker" "$fixture_root"

# Evasion 1: a '"' char literal read as a string opener swallowed the rest.
reset_fixture
cat >"$subject" <<'RS'
pub fn f(p: *const u8) -> u8 {
    let quote = '"';
    let _ = quote;
    unsafe { *p }
}
RS
expect_failure "unsafe after a '\"' char literal" "$checker" "$fixture_root"

# Evasion 2: a "/*" string literal read as a comment opener swallowed the rest.
reset_fixture
cat >"$subject" <<'RS'
pub fn f(p: *const u8) -> u8 {
    let opener = "/*";
    let _ = opener;
    unsafe { *p }
}
RS
expect_failure "unsafe after a \"/*\" string literal" "$checker" "$fixture_root"

# unsafe on a later line inside a multi-line string is still text.
reset_fixture
cat >"$subject" <<'RS'
pub fn f() -> &'static str {
    "line one
unsafe { line two }"
}
RS
expect_success "unsafe inside a multi-line string" "$checker" "$fixture_root"

# unsafe after a multi-line string closes is code.
reset_fixture
cat >"$subject" <<'RS'
pub fn f(p: *const u8) -> u8 {
    let _ = "line one
line two";
    unsafe { *p }
}
RS
expect_failure "unsafe after a multi-line string" "$checker" "$fixture_root"

# Crate-level allow is reserved for the FFI boundary.
reset_fixture
printf '%s\n' '#![allow(unsafe_code)]' 'mod subject;' >"$fixture_root/crates/kms/src/lib.rs"
expect_failure "crate-level allow outside crates/ffi" "$checker" "$fixture_root"

reset_fixture
printf '%s\n' '//! #![allow(unsafe_code)] quoted in docs only' '#![forbid(unsafe_code)]' 'mod subject;' \
  >"$fixture_root/crates/kms/src/lib.rs"
expect_success "allow attribute quoted in a doc comment" "$checker" "$fixture_root"

reset_fixture
printf '%s\n' 'mod subject;' >"$fixture_root/crates/kms/src/lib.rs"
expect_failure "crate root without an unsafe policy" "$checker" "$fixture_root"

# Experimental trees are out of scope.
reset_fixture
mkdir -p "$fixture_root/crates/experimental/toy/src"
printf '%s\n' 'pub fn f(p: *const u8) -> u8 { unsafe { *p } }' >"$fixture_root/crates/experimental/toy/src/lib.rs"
expect_success "unsafe in an experimental crate" "$checker" "$fixture_root"

expect_failure "tree without crate roots" "$checker" "$fixture_root/crates/kms"

# The real repository passes with the default root.
expect_success "repository default root" "$checker"

python3 "$repo_root/.github/scripts/lib/rust_scanner.py" >/dev/null

echo "Unsafe allowlist self-tests passed."
