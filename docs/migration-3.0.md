# Migrating from Krusty 2.0.0 to 3.0.0

## Argent legacy derivation changes keys for affected inputs

Krusty 2.0.0 re-seeded the second BIP32 tree with all 32 bytes of the intermediate
Ethereum private key. Krusty 3.0.0 strips leading zero bytes before re-seeding,
matching Argent X's numeric key encoding. The paths and account/address indices
are unchanged. Keys without leading zero bytes produce the same result.

The affected Rust APIs are `derive_stark_from_eth_key` and
`derive_argent_legacy_private_key`. The WASM exports `deriveArgentLegacyKeypair`
and `deriveArgentLegacyPublicKey`, and ArgentLegacy discovery candidates, inherit
the correction. For mnemonic-derived Ethereum keys the leading-zero case occurs
roughly once in 256 phrases; it can be identified by comparing the derived public
keys without exposing the Ethereum private key.

**An account funded or deployed using Krusty 2.0.0's affected derivation still
belongs to the old key.** Upgrading neither moves its funds nor changes its owner.
A successful 3.0 derivation or an empty 3.0 discovery result does not prove that
such a 2.0-derived account is empty or unrecoverable.

## Preserve access before upgrading

1. Keep the wallet backup and the existing account address, class/implementation,
   chain, derivation indices and account configuration. Record public addresses
   and public keys, not mnemonic/private-key material in logs or issue reports.
2. With the same inputs and indices, compare the public key/address produced by
   2.0.0 with 3.0.0 offline, using the same account configuration. Do this before
   replacing the normal recovery/signing path or funding a newly derived address.
3. If they differ, retain the 2.0.0 derivation for the existing Krusty-derived
   account. Pin the Rust recovery dependency exactly, for example
   `krusty-kms = "=2.0.0"`, or use the exact
   `@starknetfoundation/krusty-kms-wasm@2.0.0` package for its WASM path. A caret
   range such as `2` is not an exact historical implementation pin.
4. Keep that compatibility path isolated for the old account; 2.0.0 is not the
   current security-fix line. Restore/reuse the known old key for that account,
   or deliberately migrate its funds/ownership through the wallet's normal,
   separately verified transaction flow. The 3.0 library does not automate this.
5. For an existing Argent X/Ready legacy account, use 3.0's corrected derivation
   and verify the resulting public key/address against the known account before
   using it. Do not substitute a different account merely because it has the
   same mnemonic and derivation indices.

Users whose outputs match can upgrade normally. Standard Starknet, Bitcoin,
Nostr and PQB derivation profiles are not changed by the Argent correction.

## Other release changes

The release also adds PQB primitives, Nostr envelope metadata and mnemonic
encoding from entropy, alongside validation and secret-handling hardening.
See [CHANGELOG](../CHANGELOG.md) for all changes and [PQB integration](pqb-kms.md)
for its caller-owned journal and validation requirements. PQB remains a research
construction; this integration has not performed a real puzzle solve or on-chain
spend. The raw C ABI shape and existing JavaScript export names are unchanged by
the version bump, but matching function names do not preserve the affected
Argent derivation's old output.
