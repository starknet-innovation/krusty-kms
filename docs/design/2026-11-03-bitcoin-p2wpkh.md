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
- `sign_bip322_simple(private_key, address, message, encoding) -> smp-prefixed base64 witness`,
  where `Bip322Encoding::LegacyUnprefixed` drops the prefix

WASM:

```ts
deriveBitcoinP2wpkhKeypair(mnemonic: string, account_index: number, change: number, address_index: number, passphrase?: string | null): WasmBitcoinP2wpkhKeypair
signBitcoinPsbtInputs(private_key: string, psbt_base64: string, input_indices: number[]): string
signBip322Simple(private_key: string, address: string, message: string, legacy_unprefixed?: boolean): string
```

Private keys cross the boundary as 64 hex characters without `0x`, like the
Nostr bindings; `WasmBitcoinP2wpkhKeypair` zeroizes its private key on drop
and redacts it from `Debug` and `Serialize`, like the other keypair types. The
arguments follow path order (account, change, index), not the
`(address_index, account_index)` order of the BIP-44 helpers, because a BIP-84
path has a third component.

Indices arrive as `JsValue` and must be exact integers from 0 to 2^32 - 1
before the Rust range checks run: wasm-bindgen's `u32` parameters wrap
(`2^32` becomes `0`), which would derive account 0's key. `input_indices` must
be a plain array; a `Uint32Array` has already wrapped its values in JS, so it
is refused. `legacy_unprefixed` must be a boolean, `undefined` or `null`, not
any truthy value.

The mnemonic, passphrase and private-key strings are taken as owned `String`s
and wiped (`Zeroizing`) when the call returns. JS strings cannot be wiped, and
wasm-bindgen may leave a partial copy in freed memory when it re-allocates
while encoding a non-ASCII string.

## Invariants

- Mainnet only: coin type 0 and the `bc` HRP. `change` is 0 or 1; account and
  address indices must not carry the hardened bit.
- BIP-32 for this path runs on `k256` scalars and `Zeroizing` buffers (key,
  key bytes, chain code, HMAC output), not on the shared `derivation` helpers,
  whose `BigUint` and `Vec` copies are never wiped. Stack temporaries and the
  HMAC-SHA512 state (the `hmac` crate's `zeroize` feature is off) are still
  not wiped; fixing those and the shared helpers is separate work, because it
  also changes the Starknet, Tongo and Nostr derivations.
- Signatures are RFC 6979 ECDSA, low-S, SIGHASH_ALL only, ground for low R
  exactly as Bitcoin Core's `CKey::Sign(grind = true)`: plain RFC 6979 first,
  then RFC 6979 with 32 bytes of additional data, zero except a little-endian
  counter (1, 2, ...) in the first four, until `r < 2^255`. RFC 6979 section
  3.6 appends that data after the reduced digest, where libsecp256k1's
  `nonce_function_rfc6979` appends `data32`, so the bytes are Core's. A
  signature with its sighash byte is therefore at most 71 bytes, which lets a
  caller budget the vsize of a fixed-fee transaction. Grinding stops with an
  error after 256 attempts (each succeeds with probability 1/2).
- A listed PSBT input is signed only if all hold, else the call fails and
  returns no PSBT:
  - its `witness_utxo` script is this key's native P2WPKH script;
  - its `non_witness_utxo` hashes to the input's previous txid and the spent
    output equals the `witness_utxo`. BIP-143 commits only to the input's own
    amount, so this defeats a PSBT that lies about it;
  - its sighash type is absent or SIGHASH_ALL;
  - it carries no redeem or witness script, which a native P2WPKH spend
    cannot use (BIP-174 has signers check them against the UTXO);
  - it is not already finalized.
- Index lists must be non-empty, distinct and in range, so no longer than
  the PSBT's input count.
- Parsing is strict (BIP-174 version 0). The PSBT is at most 4 MiB decoded
  (longer base64 is refused before decoding). Key types are minimal
  CompactSizes, so `fd 03 00` cannot pose as an unknown type, and no map
  repeats a (type, key data) pair. Every pair is checked against one table,
  `psbt/fields.rs`, holding every field BIP-174 defines: key data (none, a
  20- or 32-byte hash, an on-curve public key, a 78-byte extended key, or a
  parsed proprietary identifier and subtype) and value (a legacy unsigned
  transaction with empty scriptSigs, a network transaction, an output, a
  strict-DER signature with a defined sighash type, a 32-bit sighash type,
  version 0, a fingerprint plus whole path elements, a witness stack, or a
  preimage that hashes to its key). PSBT version 2 fields are refused, and
  types the table does not name pass through once their type is read. As in
  Bitcoin Core, a `non_witness_utxo` on any input must be the transaction
  that input spends. Each map is kept as ordered key-value pairs, so
  `serialize(parse(x)) == x`, and signing only adds or replaces this key's
  `PARTIAL_SIG` in listed inputs. Unlisted inputs, outputs, global and
  unknown fields stay byte-identical.
- Nothing panics on hostile input. The `bitcoin` module denies
  `clippy::indexing_slicing` (tests opt out), so every index and slice is
  checked and becomes an error, and a test runs every BIP-174 vector and this
  crate's own PSBTs through the signer truncated at every offset, with every
  byte flipped, and with every length byte set to 0x00, 0xfd and 0xff.
- A global xpub's path has exactly as many elements as its depth byte.
- Transactions follow Bitcoin Core's deserialization rules: minimal
  CompactSizes, no trailing bytes, and no witness record whose stacks are all
  empty ("Superfluous witness record"). The unsigned transaction may have
  empty input and output lists, as two BIP-174 valid vectors do; a previous
  transaction may not.
- BIP-322: `address` must be this key's P2WPKH address, lowercase or
  uppercase. The result is `smp` plus the base64 witness: BIP-322 ("Types of
  Signatures") says signers MUST prefix the variant. The prefix only lets a
  verifier assume "simple" when there is none, for backward compatibility, so
  the unprefixed form is an explicit opt-in (`Bip322Encoding::LegacyUnprefixed`,
  `legacy_unprefixed = true`) for verifiers that predate the prefix, such as
  `bip322-js` 4.0.0.

## Not promised

No finalization, extraction or broadcast. No P2SH-P2WPKH, P2TR, testnet,
PSBT version 2, other sighash types, or a public-key-only derivation variant.

## Dependencies

`bitcoin_hashes` 0.14.1 (CC0-1.0, already allowed by `deny.toml`) becomes a
direct dependency of `krusty-kms` for RIPEMD-160, and `ecdsa` 0.17.0 (the
crate `k256` signs with) for its RFC 6979 additional-data entry point, which
`k256` does not re-export. Both are already in the graph, through `bip39` and
`k256`, so the lockfile gains two edges and no crate. Bech32 encoding
(one fixed-size segwit v0 program), transaction and PSBT encoding are small
enough to keep local. `rust-bitcoin` was not used: it pulls the C-backed
`secp256k1-sys`, which does not build for the browser WASM target.

## Tests

Official BIP-84 (the "abandon … about" mnemonic), BIP-143 native P2WPKH
(sighash and signature), BIP-322 (message hash, `to_spend`/`to_sign` txids,
simple signatures) and every PSBT in BIP-174's test vectors: the 20 invalid
ones are refused, and the other 25 parse, round-trip byte for byte and have
nothing this key can sign. One test per refusal above. BIP-322's simple vectors
list a Core (low-R) and a plain RFC 6979 signature; grinding reproduces the
Core one. Low-R grinding is also checked against
`tests/fixtures/bitcoin_low_r_vectors.json`, generated with `@noble/curves`
1.9.7 (an independent RFC 6979 implementation whose `extraEntropy` is section
3.6 additional data) by the same loop, including cases that needed 1 to 7
retries.
