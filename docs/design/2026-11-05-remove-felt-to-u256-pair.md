# Remove `felt_to_u256_pair`

Date: 2026-11-05. Status: accepted.

`krusty_kms::eth_signer::felt_to_u256_pair` was deprecated in 0.15.0 (#195)
because callers used it to split secp256k1 public-key coordinates that had
already been reduced modulo the Stark prime. The 0.15.0 notes promised its
removal in 0.16.0. That release deferred it so that it would land before
1.0.0. After 1.0, removing a public function needs a major version.

Removing it now. Every caller has a replacement:

- account constructor calldata: `EthSigner::public_key_calldata()`;
- `(low, high)` limbs of one coordinate: `EthCoordinate::to_u256_pair()` on
  the output of `EthSigner::public_key_xy()`.

A caller that really needs to split a `Felt` into u128 limbs can use
`Felt::to_bytes_be()` and split the 32 bytes. The crate-private
`bytes32_to_u256_pair`, which backs the supported paths, stays.

No WASM, C ABI or other workspace crate called the function. The next
release is a minor bump (or 1.0.0).
