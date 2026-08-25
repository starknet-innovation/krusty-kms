# Design: typed FFI decode failure

Date: 2026-08-24

## Problem

The struct-passing decoders introduced with canonical `KmsFelt` decoding
([`2026-08-16-canonical-kms-felt.md`](2026-08-16-canonical-kms-felt.md))
returned `Result<T, i32>`: an error *code* and a decoded *field element* in the
same two-variant, all-numeric return. Nothing but variant position kept them
apart.

CodeQL alert #56 (`rust/hard-coded-cryptographic-value`, critical) is the
visible cost. Its source is the `2` in `KMS_ERR_INVALID_INPUT`; its sink is the
`salt` parameter of `calculate_contract_address`, reached through
`kms_calculate_contract_address`. Taint tracking is not variant-sensitive
across `Result`, so `Err(KMS_ERR_INVALID_INPUT)` beside `Ok(felt)` reads as a
salt that could be the constant `2`. No such value exists at runtime — the
`Err` arm returns from the FFI function before any felt is used — but a return
type that cannot distinguish a rejected input from a decoded scalar is a design
smell, not only a checker's blind spot.

## Interface

`kms_to_felt`, `kms_slice_to_felts` and `kms_to_proj` return
`Result<T, InvalidInput>`. `InvalidInput` is a payload-free unit struct in
`crate::error` with one inherent `to_status(self) -> i32` yielding
`KMS_ERR_INVALID_INPUT`. Call sites widen explicitly, at an `extern "C"`
boundary: `Err(err) => return err.to_status()`.

Not `impl From<InvalidInput> for i32`, deliberately. `From` would make `?`
widen a decode failure into any helper returning `Result<_, i32>`, so
`Ok(kms_to_felt(k)?)` in such a helper would compile and rebuild the
code-beside-value shape one layer up — the thing this note is about. With an
inherent method that helper fails to compile, which is the outcome we want if
the alert ever comes back from a new call site. `?` still works inside
`kms_to_proj`, which propagates `InvalidInput` unchanged.

The C ABI is unchanged: same 46 exported functions, same status codes, same
header snapshot.

`read_cstr` / `read_cstr_optional` keep `Result<_, i32>`. They report two
different codes (`KMS_ERR_NULL_POINTER` as well as `KMS_ERR_INVALID_INPUT`) and
carry no cryptographic material, so a single-variant error type does not fit
them; they are out of scope here. So are the hex parsers `parse_felt` in
`proof.rs` and `calldata.rs`, which keep the same `Result<Felt, i32>` shape but
do not feed a `salt`, `nonce`, `iv`, or `password` parameter — the rule's sinks.
They can get the same treatment if that ever changes.

## Invariants

- Exactly one place turns a *struct-passing decode* failure into a number:
  `InvalidInput::to_status`. Other invalid-input paths keep returning the code
  directly and are unaffected — `kms_projective_from_affine`, for instance,
  still returns `KMS_ERR_INVALID_INPUT` when `AffinePoint::new` rejects an
  off-curve point whose coordinates both decoded fine. Same code, different
  failure, no decoded value beside it.
- A decoded value and a status code never inhabit the same `Result`.
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
`krusty_kms::{calculate_contract_address, derive_oz_account_address}`. Both
salt arms of the OZ derivation are pinned — a NULL salt meaning "salt with the
public key", and an explicit canonical salt, which is the arm that decodes a
`KmsFelt` and hands the result straight to a `salt` parameter, the alert's own
sink shape. The two are asserted to differ, so neither can pass by silently
producing the other.

Their fixtures are computed rather than literal felts, matching `test_bytes` in
`calldata.rs`: a literal reaching a `salt` parameter is what this rule reports,
and a fix should not trade one alert for another.

## Verification

Run against the same CodeQL the workflow uses (CLI 2.26.3, `rust-queries`
0.1.40, `--build-mode=none`), whole-workspace database, before and after:

- before: 87 results for the rule, including
  `crates/ffi/src/error.rs:11` → `crates/ffi/src/address.rs:55` and
  → `crates/kms/src/account.rs:148`, which is alert #56 exactly.
- after: 86 results. That path is gone, nothing in `crates/ffi` is reported,
  and no result is new — the fix removes one finding and adds none.

The remaining 86 are pre-existing and out of scope: constants reaching `salt`
parameters from `#[cfg(test)]` modules, `tests/` directories, and examples.
None of them is an open alert on the repository, and a local run sees more than
the hosted one because it extracts dependency sources that taint can pass
through; the before/after delta is what this note claims, not the absolute
count.
