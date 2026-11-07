# Read unprefixed WASM felt digits as decimal

Date: 2026-11-07. Status: proposed, held for 2.0.0.

## Problem

`krusty-kms-wasm` parsed felt strings two ways. `encodeFelt` read unprefixed
digits as decimal, while calldata compilation, transaction and typed-data
hashes, account addresses, signing, hashing, points and proofs read them as
hexadecimal. The same string, such as `"1000"`, therefore meant 1000 in one
export and `0x1000` in another. A caller who passed a decimal token amount to
`compileCalls` signed a different amount than intended.

## Decision

Route every WASM felt input through one parser, `felt_input::parse_felt`:

- `0x` or `0X` prefix: hexadecimal.
- Digits only: decimal.
- Anything else, including unprefixed hex letters: rejected.
- Values at or above the Stark field modulus: rejected before either upstream
  parser can reduce them.

Secret felt inputs follow the same rule. Hex-only inputs that are not felts,
such as seeds, Nostr keys and byte strings, keep their existing parsing.

## Compatibility

This is a **Breaking** change. On 1.0, `isValidFelt` and
`isValidStarkPrivateKey` documented unprefixed hex as valid input, and most
felt paths read digit-only strings as hex. A caller relying on that contract
gets a different key, address, hash or signature without an error. Under the
1.x semver policy it waits for the 2.0.0 release. Callers that mean
hexadecimal must add `0x`. Export signatures and output formats are unchanged.

## Guardrail baselines

To keep every file under the 350-line soft limit, the `compileCalls` tests move
to `calldata/tests.rs` and the account class-preset tests move to
`account/class_preset_tests.rs`. The file-size baseline only goes down:
`crates/wasm/src/lib.rs` (398 to 395 lines) and `crates/wasm/src/types.rs`
(506 to 504 lines).

## Verification

Regression tests cover a `1000000000000000000` transfer limb, V3 nonce and
calldata, typed-data account addresses, OZ address derivation, secret felts and
field-modulus rejection. `bash tools/check.sh all` passes.
