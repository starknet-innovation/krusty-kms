# Preserve Ethereum public key coordinates

## Problem

`EthSigner::public_key_xy()` returned two Starknet `Felt` values. A secp256k1
coordinate can exceed the Stark prime, so converting its bytes into a `Felt`
reduces the value and changes the public key. Splitting that reduced value into
u256 calldata cannot recover the original coordinate.

## Contract and invariants

`public_key_xy()` now returns `(EthCoordinate, EthCoordinate)`. The type lives in
`krusty_kms::eth_signer` (re-exported as `krusty_kms::EthCoordinate`) and has a
private 32-byte big-endian representation. Only the signer constructs it, from
the validated uncompressed public key. `public_key_calldata()` delegates to it,
so there is a single SEC1 extraction to audit.

- `to_bytes_be()` returns the exact coordinate bytes from the SEC1 public key.
- `to_u256_pair()` returns `(low, high)`, each a Felt holding at most 128 bits.
  Concatenating the 16-byte high limb and 16-byte low limb recovers the exact
  original 32 bytes, without reduction modulo the Stark prime.
- There is deliberately no `PartialEq<Felt>` for `EthCoordinate`. A coordinate
  is a 256-bit integer, not a field element; comparing the two would let a caller
  written against the old reduced `Felt` return type keep compiling with a
  changed meaning. Compare `to_bytes_be()` or the `to_u256_pair()` limbs.
- Extracting and encoding coordinates is infallible for an existing signer.
  Signing behavior and the FFI/WASM surfaces are unchanged.

The wrapper keeps a full coordinate distinct from a Stark field element and
provides the calldata conversion without permitting invalid public construction.
It adds no dependencies.

## Compatibility and migration

Changing the return type is a breaking Rust API change. Callers that explicitly
name the coordinate type use `krusty_kms::eth_signer::EthCoordinate` instead of
`Felt`. Replace `felt_to_u256_pair(&x)` with `x.to_u256_pair()`:

```rust
let (x, y) = signer.public_key_xy();
let (x_low, x_high) = x.to_u256_pair();
let (y_low, y_high) = y.to_u256_pair();
let calldata = [x_low, x_high, y_low, y_high];
```

`public_key_calldata()` and its known-answer tests are retained from current
`main`. It remains the direct constructor-calldata API. The deprecated
`felt_to_u256_pair()` remains available for values that already are Felts; it
cannot restore coordinates previously reduced into Felts. No production callers
of `public_key_xy()` exist within this repository. The next release containing
this change needs a minor version increment under the repository's pre-1.0
release policy; this fix does not perform that release.

## Regression coverage

The byte comparison checks both coordinates against the SEC1 public key.
The round-trip regression uses a deterministic key whose two coordinates exceed
the Stark prime. It checks that reduction changes each value, verifies both
128-bit limb bounds and ordering, and reconstructs both original coordinates
from their calldata pairs. Tests live in `crates/kms/src/eth_signer/tests.rs`,
keeping the module under the file-size guardrail without a baseline bump.

## Compatibility decision

The deprecated function shipped in 0.15.0 the same day as this change and
returned a wrong value for roughly 97% of keys, so there is no working caller
behavior to preserve. crates.io lists no reverse dependencies outside this
workspace and no public dependent references the Eth signer. The release
containing this change is therefore a pre-1.0 minor bump (0.16.0) with the
migration above, rather than an additive method under a new name. Note that
`cargo-semver-checks` has no lint for a changed return type on an inherent
method, so CI does not enforce the bump; `docs/crates-release.md` records it as
a reviewer decision.
