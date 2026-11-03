# Design: Bitcoin mainnet P2WPKH keys, PSBT inputs and BIP-322

Date: 2026-11-03

## Problem

A wallet that holds a BIP-39 phrase for a Bitcoin payment key needs three
operations from that key: derive it, sign selected inputs of a PSBT someone
else built, and sign a BIP-322 message to prove it owns the address. Krusty
owns wallet key derivation and signing for its callers, so these belong here
rather than in a JavaScript fallback. Krusty already has secp256k1 through
`k256` (Nostr), but no BIP-84 path, ECDSA transaction signing, PSBT or BIP-322.

## Interface

Rust (`krusty_kms`, new `bitcoin` module):

- `derive_bitcoin_p2wpkh_keypair(mnemonic, account_index, change, address_index, passphrase)`
  returns `BitcoinP2wpkhKeyPair { private_key, public_key (33-byte compressed),
  address (bc1q…), path }`, at `m/84'/0'/account'/change/index`.
- `sign_bitcoin_psbt_inputs(private_key, psbt_base64, input_indices) -> base64 PSBT`
- `sign_bip322_simple(private_key, address, message) -> base64 witness`

WASM mirrors them as `deriveBitcoinP2wpkhKeypair`, `signBitcoinPsbtInputs`
and `signBip322Simple`. Private keys cross the boundary as 64 hex characters
without `0x`, like the Nostr bindings; `WasmBitcoinP2wpkhKeypair` zeroizes its
private key on drop and redacts it from `Debug` and `Serialize`, like the other
keypair types. The arguments follow path order (account, change, index), not
the `(address_index, account_index)` order of the BIP-44 helpers, because a
BIP-84 path has a third component.

## Invariants

- Mainnet only: coin type 0 and the `bc` HRP. `change` is 0 or 1; account and
  address indices must not carry the hardened bit.
- Signatures are RFC 6979 ECDSA, low-S, SIGHASH_ALL only. Low-R grinding is not
  done, so BIP-322 output matches the plain RFC 6979 signature listed in the
  BIP-322 vectors rather than the Bitcoin Core one; both verify.
- A listed PSBT input is signed only if all hold, else the call fails and
  returns no PSBT:
  - its `witness_utxo` script is this key's native P2WPKH script;
  - its `non_witness_utxo` hashes to the input's previous txid and the spent
    output equals the `witness_utxo`. BIP-143 commits only to the input's own
    amount, so this defeats a PSBT that lies about it;
  - its sighash type is absent or SIGHASH_ALL;
  - it is not already finalized.
- Index lists must be non-empty, distinct and in range.
- Parsing is strict (BIP-174 version 0): minimal CompactSizes, no trailing
  bytes, no duplicate keys, the key shapes BIP-174 fixes, no version-2-only
  fields, empty scriptSigs in a legacy-serialized unsigned transaction. Each
  map is kept as ordered key-value pairs, so `serialize(parse(x)) == x`, and
  signing only adds or replaces this key's `PARTIAL_SIG` in listed inputs.
  Unlisted inputs, outputs, global and unknown fields stay byte-identical.
- BIP-322: `address` must be this key's P2WPKH address, lowercase or
  uppercase. The result is the unprefixed base64 witness. BIP-322 1.0.0 adds an
  `smp` variant prefix but lets verifiers assume "simple" without one; the
  unprefixed form is what earlier BIP-322 implementations, such as
  `bip322-js`, produce and verify.

## Not promised

No finalization, extraction or broadcast. No P2SH-P2WPKH, P2TR, testnet,
PSBT version 2, other sighash types, or a public-key-only derivation variant.

## Dependencies

`bitcoin_hashes` 0.14.1 (CC0-1.0, already allowed by `deny.toml`) becomes a
direct dependency of `krusty-kms` for RIPEMD-160. It is already in the graph
through `bip39`, so the lockfile gains one edge and no crate. Bech32 encoding
(one fixed-size segwit v0 program), transaction and PSBT encoding are small
enough to keep local. `rust-bitcoin` was not used: it pulls the C-backed
`secp256k1-sys`, which does not build for the browser WASM target.

## Tests

Official BIP-84 (the "abandon … about" mnemonic), BIP-143 native P2WPKH
(sighash and signature), BIP-322 (message hash, `to_spend`/`to_sign` txids,
simple signatures) and every BIP-174 invalid-PSBT vector; round trips over the
BIP-174 valid vectors; one test per refusal above.
