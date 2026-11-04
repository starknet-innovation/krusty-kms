# Eth public-key limbs and C ABI transfer calldata

Date: 2026-11-04. Status: accepted. Origin: security audit findings H-1 and
H-2 (audit of ce8d00ef).

## Problem

**H-1.** `EthSigner::public_key_xy` built each secp256k1 coordinate with
`Felt::from_bytes_be_slice`, which reduces modulo the Stark prime (about
2^251). A coordinate is 256 bits, so for roughly 31 of every 32 keys the
value no longer encoded the signer's key, and `felt_to_u256_pair` split that
reduced value into `(low, high)`. The doc comment presented the pair as OZ
Ethereum account constructor calldata. An account address derived from it
cannot be deployed, and funds sent there are stuck. The only test compared
the function with itself.

**H-2.** `kms_encode_transfer_calls` in the C ABI crate emitted the Tongo
`transfer` calldata starting at `transferBalance` with a single hint. The
contract's `Transfer` struct, and `krusty_kms_client::build_transfer_call`,
have eleven fields: `from`, `to`, `transferBalance`, `transferBalanceSelf`,
`hintTransfer`, `hintLeftover`, `auxiliarCipher`, `auxiliarCipher2`,
`proof`, `auditPart`, `auditPartTransfer`. The FFI calldata was ten felts
short and misaligned from the first field, so every transfer built through
the Swift, JVM, Dart or C wrappers reverted on chain. The FFI test pinned the
wrong shape.

## Decision

- `EthSigner::public_key_calldata(&self) -> [Felt; 4]` returns
  `[x_low, x_high, y_low, y_high]` from the 65-byte SEC1 encoding with the
  same `bytes32_to_u256_pair` the signature path uses, with no `Felt`
  round-trip. `public_key_xy` and `felt_to_u256_pair` are deprecated rather
  than removed, because `cargo-semver-checks` rejects a removed public item
  without a minor bump; their behaviour is unchanged and their docs now say
  what they do. They go in the next minor release.
- The C ABI transfer encoder takes `sender_public_key` and
  `recipient_public_key` (the `0x` + `x` + `y` form the proof parameters
  already use) and `hint_leftover_ciphertext_hex` / `hint_leftover_nonce_hex`
  as required fields, and emits the eleven fields in the client's order. The
  old parameter shape fails with `KMS_ERR_JSON` instead of encoding a call
  that reverts. The C header is unchanged.
- `crates/ffi/src/calldata.rs` keeps the encoder within its function-size
  baseline by moving the layout into `transfer_calldata`, and within its
  file-size baseline by moving `mod tests` to `calldata/tests.rs`, the
  convention the gateway, sdk and client crates already follow. The
  file-size baseline for `calldata.rs` ratchets down (1201 → 815 lines) and
  lists `calldata/tests.rs` at 476; `kms_encode_transfer_calls` leaves the
  function-size baseline. No baseline grows.

## Laws (tested)

1. `public_key_calldata` for the two Hardhat development keys equals the
   limbs of their published uncompressed public keys, computed outside the
   crate.
2. For any key, `public_key_calldata` equals the `u128` big-endian splits
   of bytes `1..33` and `33..65` of `public_key_uncompressed`.
3. The FFI transfer calldata positions `0..4` are the sender's and
   recipient's `(x, y)`, `12..18` and `18..24` are two distinct `AEBalance`
   hints in that order, `24..32` are the auxiliary ciphers, then the proof
   felts and two `Some` audit options; total length is `32 + proof_len +
   2 × 22`.
4. The pre-fix parameter shape is rejected.

## Alternatives considered

- Carrying `from` and `to` in the proof result JSON so the encoder cannot be
  handed a mismatched key. Rejected for now: `proof.rs` is at its file-size
  baseline, the transfer transcript already binds both keys so a mismatch
  reverts rather than misdirects, and the client API also takes them as
  explicit parameters.
- Removing the two deprecated `EthSigner` helpers now. Deferred to the next
  minor bump for the semver reason above.
