# Wipe secrets in shared BIP-32 derivation and HMAC

Date: 2026-11-03. Status: proposed.

## Problem

Every Starknet, Argent, Braavos, Tongo, and Nostr key goes through
`derivation.rs`. Its BIP-32 step held the parent key, `IL`, and the child in
`BigUint` and serialized the child through a `Vec`. Grinding did the same with
each SHA-256 candidate. None of these is wiped on drop, and arithmetic on them
leaves reallocated buffers behind.

The HMACs keyed by secrets used `hmac` 0.13. Its `zeroize` feature only
forwards to `digest/zeroize`. With `sha2`'s `zeroize` feature, the two
compression states inside `HmacCore` and the block buffer are wiped when the
MAC drops, but three values in `hmac` are plain locals and stay in memory:

- `new_from_slice`'s padded key block, which holds `key ^ opad` when it
  returns, so it is the key. It is `#[inline(always)]`, so the block sits in
  the caller's frame.
- `get_der_key`'s hash of a key longer than one block.
- the inner hash in `finalize_fixed_core`.

No feature of the locked `hmac`, `digest` 0.11.3, or `block-buffer` 0.12.1
reaches these.

## Change

- `zeroizing_hmac` (crate-private) adds `hmac::<D, N>(key, message_parts)`, the
  same helper the QSB-HORS branch (#187) uses, and `hkdf_sha256_expand::<L>`.
  The padded key sits in a `Zeroizing` buffer, the inner hash is wiped once
  used, and the output is `Zeroizing<[u8; N]>`. The `D: ZeroizeOnDrop` bound
  holds only with `sha2`'s `zeroize` feature, which `krusty-kms` now enables,
  so removing the feature breaks the build. Keys longer than one block are
  refused rather than hashed: no caller needs one.
- Every secret-keyed or secret-message HMAC in the crate uses it: the BIP-32
  master key, BIP-32 child derivation, and NIP-44's HKDF-Extract, HKDF-Expand,
  and message MAC. The tag is compared with `subtle`. `hkdf` is no longer a
  dependency, and `hmac` is kept only as the tests' differential oracle.
- BIP-32 arithmetic uses `k256::Scalar` in `Zeroizing`: `IL` through
  `from_repr` (which rejects `IL >= n`), the parent through `Reduce` (mod n,
  as the old `%` did), and a constant-time zero check. Grinding uses
  `crypto-bigint`'s `U256` in `Zeroizing`. Its bound
  `2^256 - (2^256 mod n)` is a compile-time constant, and a test checks it
  against the big-integer bound. `crypto-bigint` was already in the graph
  through `k256` and `krusty-kms-crypto`, and it is now a direct dependency of
  `krusty-kms` with the workspace `zeroize` feature.
- WASM: the nine exports that take an owned `passphrase: Option<String>` hold
  it in `Zeroizing`. `WasmKeypair::new` and `WasmStarkXOnlyKeypair::new` now
  build the object before validating the public key, so a rejected private key
  is wiped when the object drops instead of being freed as a plain `String`.
  `types.rs` grows by four lines for this, from 502 to 506. Its baseline moves
  with it, and the `derivation.rs` baseline drops from 703 to 688.

## Laws

- Outputs are byte-identical. Every existing vector, cross-test, and NIP-44
  vector passes unchanged. `derivation/reference_test.rs` keeps the old
  big-integer arithmetic as a reference and compares it with the new code on
  2,048 grinding seeds, 512 child derivations, 32 full paths, and parent keys
  at 0, 1, n-1, n, and 2^256-1.
- `hmac` matches RFC 4231 cases 1-4 for SHA-256 and SHA-512, and the `hmac`
  crate for every key length up to one block. The 131-byte keys of cases 6
  and 7 are refused. `hkdf_sha256_expand` matches RFC 5869 cases 1 and 3.
- `Sha256`, `Sha512`, `Scalar`, and `U256` wipe themselves: compile-time trait
  checks, plus run-time checks for `Scalar` and `U256`.
- Error cases are unchanged: `IL >= n`, a zero child, and an invalid
  non-hardened parent still fail with the same messages.

## Not covered

What Rust cannot promise is not claimed: copies the compiler makes when moving
values, register spills, and temporaries inside `k256`, `crypto-bigint`, and
the SHA-2 compression and finalization functions. The rest is listed in the
inventory below.

## Inventory

Sites where seeds, private scalars, chain codes, HMAC/KDF keys, or
intermediates go through non-wiping types or HMAC/KDF state on `main`.

| Site | Before | After |
| --- | --- | --- |
| BIP-32 master key `HMAC-SHA512("Bitcoin seed", seed)` | `hmac` crate: inner hash and padded key in plain locals | `zeroizing_hmac` |
| BIP-32 child: HMAC keyed by chain code over the parent key | `hmac` crate | `zeroizing_hmac` |
| BIP-32 child: `IL`, parent, and child | `BigUint`, child serialized through `Vec` | `Zeroizing<Scalar>`, `FieldBytes` wiped |
| `grind_key`: SHA-256 state, digest, candidate, `k` | unwiped hasher, `BigUint`, `Vec`, padded array | `ZeroizeOnDrop` hasher, wiped digest, `Zeroizing<U256>` |
| NIP-44 HKDF-Extract over the ECDH secret, HKDF-Expand, message MAC | `hkdf` and `hmac` crates | `zeroizing_hmac` |
| WASM owned passphrase (9 exports) | plain `String` | `Zeroizing` |
| WASM keypair constructors' rejected `private_key` | freed unwiped on error | wiped on drop |
| BIP-39 seed (`bip39` PBKDF2-HMAC-SHA512, normalized passphrase) | `bitcoin_hashes` engines are not wiped | unchanged; seed already `Zeroizing` at call sites |
| scrypt (`encryption`, `keystore`) | `pbkdf2`'s HMAC padded-key locals; scrypt's `B`/`V`/`T` vectors | SHA-2 states now wiped; the rest unchanged |
| Stark signing (RFC 6979 via `starknet-crypto` and `rfc6979` 0.5) | HMAC padded-key locals; nonce `k` and key as `Felt` | SHA-2 states now wiped; the rest unchanged |
| `EthSigner` ECDSA (RFC 6979 via `rfc6979` 0.6 `SimpleHmac`) | `opad_key` block field | SHA-2 states now wiped; the rest unchanged |
| STRK20 viewing key and fold | Pedersen output and reductions in `BigUint` | unchanged |
| Keystore v3 MAC `Keccak256(mac_key \|\| ciphertext)` | `sha3` state (its `zeroize` feature is off) | unchanged |
| AEAD / stream cipher key schedules | `chacha20poly1305`, `chacha20`, and `ctr` `zeroize` features are off | unchanged |
| Tongo audit key (SDK): ECDH x hashed to a key | digest and returned `[u8; 32]` | SHA-2 state now wiped; the rest unchanged |
| Returned secrets: `Felt` keys, `[u8; 32]` Nostr key, decrypted `String`s, discovery candidates' hex keys | public API types | unchanged; the caller's to wipe |
| WASM `&str` secrets (mnemonic, private key, password) | wasm-bindgen's `Box<str>` copy, freed unwiped after the call | unchanged |
| JS strings on either side of the WASM boundary | cannot be wiped from Rust | unchanged |

"SHA-2 states now wiped" means any build that includes `krusty-kms`. Cargo
unifies `sha2` 0.11's `zeroize` feature across the graph, so it also reaches
`k256`, `rfc6979`, `pbkdf2`, and `scrypt`.

## Follow-ups

- Take WASM mnemonics, private keys, and passwords as owned `String`s held in
  `Zeroizing`, as the Bitcoin branch (#188) does. Its JS API is unchanged, but
  the export snapshot changes.
- Move STRK20 viewing-key arithmetic to `crypto-bigint`.
- #187 and #188 landed with their own copies of the wiped HMAC for their new
  paths; this branch moves both onto `zeroizing_hmac`: `bitcoin/bip32.rs`'s
  HMAC-SHA512, and `qsb_hors/key.rs`, whose copy and duplicate tests go.
