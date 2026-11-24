# Migrating from Krusty 3.x to 4.0.0

Krusty 4.0.0 does not change any key or address derivation. Mnemonics, BIP-32
paths, account classes and discovery produce the same keys and addresses as
3.x. The release is a major version because existing calls now reject some
inputs they accepted, Tongo audit hints change format, and a public type comes
from a newer `async-nats`.

## Encrypted private keys and keystores

New direct encryption and the default WASM decryption are bounded to a 256 MiB
scrypt budget (N up to 2^18 with r=8).

- **Ciphertext created with N=2^19 or 2^20 is still recoverable.** In Rust,
  `decrypt_private_key` keeps the old range for trusted, caller-owned metadata.
  In WASM, `decryptPrivateKey` now returns a `SERIALIZATION_ERROR` naming
  `decryptPrivateKeyHighCost`; call that export deliberately for recovery, then
  re-encrypt with N at most 2^18. The wire format is unchanged.
- **Untrusted metadata:** use `decrypt_private_key_bounded` in Rust instead of
  `decrypt_private_key`, so a hostile `scrypt_n` cannot request about 1 GiB.
- **Tighter input checks** on existing entry points:
  - direct `EncryptedKey.salt` must be exactly 16 bytes;
  - direct plaintext is capped at 1 MiB minus the 16-byte tag, and direct
    ciphertext at 1 MiB;
  - `encrypt_keystore` / `encryptKeystore` reject plaintext over 4096 bytes;
  - v3 keystore imports reject N·r·p above 2^21 and KDF salts over 128 bytes.
- **WASM scrypt-N arguments must be JavaScript numbers.** Numeric strings that
  wasm-bindgen used to coerce (for example `"16384"`) now fail with a
  structured `SERIALIZATION_ERROR`. Errors created from `WasmError` also carry
  their `code` property.

## Tongo audit hints

Auditor-enabled Tongo operations now emit the format the pinned
`@fatsolutions/tongo-sdk` 1.3.2 auditor reads. The shared serializer and C ABI
emit different felts for the same input bytes, and `AEBalance` gained layout
fields.

- Code that builds `AEBalance` with a struct literal or matches it exhaustively
  must add the new fields (or use `..`).
- To read hints written by Krusty 3.x or earlier, try every
  `AEBalance::candidates()` byte layout with both `decrypt_as_auditor_with_context`
  and the deprecated `decrypt_as_auditor`. A decrypted balance is
  sender-controlled; check it against the ElGamal balance or proof.
- `encrypt_for_auditor` and `decrypt_as_auditor` keep the legacy Krusty format
  and are deprecated. Use the `_with_context` functions for Tongo operations.
- An audited balance must fit in `u32` and the operation nonce in `u64`;
  auditor-enabled operations fail otherwise.

## NATS multisig coordinator (`krusty-kms-client`, `nats` feature)

`krusty-kms-client` now depends on `async-nats` 0.53. `NatsMultisigCoordinator::new`
takes an `async_nats::Client` from that version: upgrade your own `async-nats`
dependency to 0.53 if you pass a client in. `NatsMultisigCoordinator::connect`
inherits 0.53's stricter TLS behaviour: TLS settings require TLS on every
server, and discovered servers are verified against trusted names. See the
`async-nats` 0.53 release notes if you connect with `tls://` URLs or clusters.
0.52 also stops a header value containing a line break from crashing a
subscriber's connection.

See the [CHANGELOG](../CHANGELOG.md) for the complete list.
