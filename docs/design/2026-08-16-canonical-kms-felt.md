# Design: canonical `KmsFelt` decoding

Date: 2026-08-16

Superseded in part by
[`2026-08-24-typed-ffi-decode-failure.md`](2026-08-24-typed-ffi-decode-failure.md):
the decoders now return `Result<_, InvalidInput>` rather than `Result<_, i32>`.
The canonicality rule and the `KMS_ERR_INVALID_INPUT` status code are unchanged.

## Problem

M-25 taught the hex and bytes parsers to reject values `>= p` instead of
reducing them. `kms_to_felt` still used `Felt::from_bytes_be_slice`, so any
caller that populated a `KmsFelt` from raw 32 bytes (JNI, Swift, Dart) could
sign, hash, or create a Tongo account with a different field element than the
buffer they supplied.

## Interface

`kms_to_felt` now returns `Result<Felt, i32>` and fail-closes with
`KMS_ERR_INVALID_INPUT` unless the 32-byte buffer is `<= Felt::MAX`
(`p - 1`) as a big-endian integer. `kms_slice_to_felts` applies the same
check to arrays. The C ABI function signatures are unchanged; only the
error code for non-canonical struct values changes (previously those
calls succeeded with a reduced scalar).

The bound is compared against the public `Felt::MAX` encoding before
`from_bytes_be_slice`, so secret-bearing inputs (private keys, ElGamal
scalars) do not get an extra `to_bytes_be()` plaintext copy on the stack.

## Invariants

- Every FFI entry point that reads a `KmsFelt` goes through the checked
  decoder, including hashes, points, and address helpers.
- Projective points decode `x`, `y`, and `z` before the `z == 0` identity
  fast path, so a canonical zero Z cannot smuggle a non-canonical X or Y.
- Canonical encodings, including `Felt::MAX` (`p - 1`) and leading-zero
  short values produced by `felt_to_kms`, still decode.

## Failure modes

Bindings that previously stuffed a 32-byte integer `>= p` into `KmsFelt`
now receive `KMS_ERR_INVALID_INPUT` instead of silently aliasing. Callers
that already used `kms_felt_from_hex` / `kms_felt_from_bytes_be` are
unchanged.
