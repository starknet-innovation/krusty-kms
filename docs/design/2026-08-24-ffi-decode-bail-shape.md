# Design: how a `KmsFelt` decode bails

Date: 2026-08-24

## Problem

CodeQL alert #56 (`rust/hard-coded-cryptographic-value`, critical) reports the
`2` in `KMS_ERR_INVALID_INPUT` as a hard-coded salt. Its sinks are both `salt`
parameters of `calculate_contract_address`: the direct call in
`kms_calculate_contract_address`, and the one inside
`krusty_kms::derive_oz_account_address` reached from
`kms_derive_oz_account_address`.

The reported path runs through the decode bail:

```rust
let s = match kms_to_felt(&*salt) {
    Ok(felt) => felt,
    Err(code) => return code, // KMS_ERR_INVALID_INPUT
};
// ... calculate_contract_address(&s, ...)
```

The `return` in the error arm has type `!` and coerces to the match's type, and
the analysis models it as *a value the match can produce*. So `s` inherits the
error constant, and a constant reaching a parameter named `salt` is exactly what
this rule reports. No such value exists at runtime — that arm has already left
the function — but every early return from a match arm that binds a value has
this shape.

What is *not* the cause is worth stating, because the obvious reading is wrong.
It is not `Result<Felt, i32>` putting a code and a value in the same two-variant
return: an untyped decoder that bails with `let ... else` is clean, and a
*typed* decoder that bails from a match arm is still reported. Measured on a
minimal reproduction, against the same CodeQL the workflow uses:

| bail shape | decoder error type | reported |
| --- | --- | --- |
| `match` arm + `return` | `i32` | yes |
| `match` arm + `return` | `InvalidInput` | yes |
| `let ... else` | `i32` | no |
| `let ... else` | `InvalidInput` | no |
| `if let ... else` | `InvalidInput` | no |
| trailing `match`, no early return | either | no |
| inner `Result` closure + `?` | `InvalidInput` | no |

A match arm returning `err.into()` through a `From` impl also reads clean, but
only because that trait call is not summarised. That is a property of the model,
not of the code, so it is not the fix.

## Interface

Two changes, deliberately separate.

**The fix.** Every `KmsFelt` / `KmsProjectivePoint` decode bails with
`let ... else` instead of a match arm:

```rust
let Ok(s) = kms_to_felt(&*salt) else {
    return InvalidInput.to_status();
};
```

This is also the shorter and more direct spelling — `let ... else` is the
construct for "bind or leave" — so it holds up without the alert.

**A type change carried alongside it.** `kms_to_felt`, `kms_slice_to_felts` and
`kms_to_proj` return `Result<T, InvalidInput>` rather than `Result<T, i32>`.
`InvalidInput` is a payload-free unit struct in `crate::error` with one inherent
`to_status(self) -> i32` yielding `KMS_ERR_INVALID_INPUT`.

It does not close the alert by itself — see the table — and it is not claimed
to. It is here because a decoder whose return type cannot tell a rejected input
from a decoded scalar is worth fixing anyway, and because it gives the numeric
contract with C callers exactly one home.

Not `impl From<InvalidInput> for i32`, deliberately: `From` would let `?` widen
a decode failure into any helper returning `Result<_, i32>`, putting a status
code back beside a decoded value one layer up.

The C ABI is unchanged: same 46 exported functions, same status codes, same
header snapshot.

Out of scope: `read_cstr` / `read_cstr_optional` keep `Result<_, i32>` (they
report two different codes and carry no cryptographic material), and so do the
hex parsers `parse_felt` in `proof.rs` and `calldata.rs`. None of them bails
from a match arm into a `salt`, `nonce`, `iv`, or `password` parameter, which is
what this rule's sinks are.

## Invariants

- No `KmsFelt` / `KmsProjectivePoint` decode bails from inside a match arm.
  Turning one back into a `match` re-creates alert #56.
- Exactly one place turns a struct-passing decode failure into a number:
  `InvalidInput::to_status`. Other invalid-input paths still return the code
  directly and are unaffected — `kms_projective_from_affine`, for instance,
  returns `KMS_ERR_INVALID_INPUT` when `AffinePoint::new` rejects an off-curve
  point whose coordinates both decoded fine. Same code, different failure, no
  decoded value beside it.
- Every FFI entry point that rejects a non-canonical `KmsFelt` still returns
  `KMS_ERR_INVALID_INPUT`.

## Failure modes

None for C callers: no signature, no status code, and no accepting-path
behaviour changes. `krusty-kms-cabi` is `publish = false` with
`crate-type = ["cdylib"]`, so the Rust-level signature change binds no
downstream Rust consumer and is not covered by `cargo-semver-checks`.

Regression tests in `crates/ffi/src/address.rs` pin the boundary: a
non-canonical salt, class hash, deployer address, or constructor calldata
element returns `KMS_ERR_INVALID_INPUT`, and accepted inputs still agree with
`krusty_kms::{calculate_contract_address, derive_oz_account_address}`. Both salt
arms of the OZ derivation are pinned — a NULL salt meaning "salt with the public
key", and an explicit canonical salt, which is the arm that decodes a `KmsFelt`
and hands the result straight to a `salt` parameter, the alert's own sink shape.
The two are asserted to differ, so neither can pass by silently producing the
other.

Their fixtures are computed rather than literal felts, matching `test_bytes` in
`calldata.rs`: a literal reaching a `salt` parameter is what this rule reports,
and a fix should not trade one alert for another.

## Verification

Run against the same CodeQL the workflow uses (CLI 2.26.3, `rust-queries`
0.1.40, `--build-mode=none`), whole-workspace database, on `main` (`45c0b4e1`)
and on this branch:

- `main`: 87 results for the rule, including
  `crates/ffi/src/error.rs:11` -> `crates/ffi/src/address.rs:55` and
  -> `crates/kms/src/account.rs:148`, which is alert #56 exactly.
- branch: 86 results. That path is gone, nothing in `crates/ffi` is reported,
  and no result is new.

The bail-shape table above comes from a separate minimal crate carrying one
function per shape, analysed the same way. Building it was the point. The first
attempt at this fix -- typed error, still bailing from a match arm, widening
with `err.into()` -- read clean only because the `From` call was not summarised.
Replacing `From` with an inherent `to_status()`, which is the better Rust,
brought the alert straight back. The reproduction is what turned that from a
surprise into a table.

The remaining 86 are pre-existing and out of scope: constants reaching `salt`
parameters from `#[cfg(test)]` modules, `tests/` directories, and examples. None
of them is an open alert on the repository, and a local run sees more than the
hosted one because it extracts dependency sources that taint can pass through;
the delta is what this note claims, not the absolute count.
