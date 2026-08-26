# Nostr application-data gift wraps

## Contract

Krusty derives the existing SLIP-44 Nostr identity, wraps bounded application data for one
recipient with NIP-44/NIP-59, and opens gift wraps addressed to that identity. The WASM facade
accepts a mnemonic and returns only public event data; derived private key bytes never cross into
JavaScript.

The inner rumor is NIP-78 application-specific data (kind 30078) with one caller-provided `d`
identifier. The opener verifies the outer event, seal signature, sender match, kind, identifier,
and payload bounds before returning the sender public key and content.

## Invariants and failures

- Nostr keys use the existing `m/44'/1237'/account'/0/index` derivation.
- Application identifiers are 1-128 printable ASCII bytes; content is 1-32,768 UTF-8 bytes so
  both nested NIP-44 envelopes stay below the protocol's 65,535-byte plaintext limit.
- Events and recipient keys are parsed strictly; NIP-44 compatibility is pinned by the official
  v2 known-answer vector.
- Authentication, decryption, kind, identifier, or size failures return `KmsError` and no content.
- No relay, persistence, contact, or messaging policy belongs in Krusty.

The implementation reuses Krusty's pure-Rust `k256` BIP-340 signer and RustCrypto's `chacha20`,
`hkdf`, `hmac`, and `sha2` primitives. This avoids the C-backed `secp256k1-sys` dependency that
cannot compile for Krusty's browser WASM target.
