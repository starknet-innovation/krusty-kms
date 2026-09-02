# Shared Test Vectors

> **Do not fund, reuse, or import anything in this directory.**
>
> These vectors contain **publicly known test mnemonics and private keys**.
> They exist only to make derivation, signing, and proof tests deterministic
> across language ports. Anyone can read them, so any account they control is
> already compromised: never send funds to an address derived from them and
> never load them into a wallet.

These checked-in files define the compatibility contract for the krusty-kms crates.

Core vectors:
- `mnemonic_seed_vectors.json` - BIP-39 seed derivation
- `coin_derivation_vectors.json` - BIP-44 Starknet and Tongo derivation
- `nostr_derivation_vectors.json` - Nostr SLIP-44 derivation
- `account_address_vectors.json` - OpenZeppelin account address derivation
- `stark_signing_vectors.json` - deterministic Stark ECDSA signing
- `nostr_signing_vectors.json` - deterministic Nostr BIP-340 signing

SDK proof vectors:
- `../../prover-vectors.json` - checked-in Tongo proof-generation vectors

Cross-language parity support:
- `../../cross-compat-vectors.json` - Rust proof outputs consumed by external
  compatibility tooling

All hex strings are lowercase. Felt values are `0x`-prefixed; byte strings are
plain lowercase hex unless a file says otherwise.
