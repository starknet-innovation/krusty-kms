# Zig KMS v1 Status

## Implemented

- Stable C ABI header and exported symbols are built and linkable from `libkms`.
- Implemented ABI endpoints:
  - `kms_get_abi_version`
  - `kms_get_version_string`
  - `kms_felt_from_hex`
  - `kms_felt_to_hex`
  - `kms_felt_from_bytes_be`
  - `kms_felt_to_bytes_be`
  - `kms_projective_from_affine`
  - `kms_projective_to_affine`
  - `kms_pedersen_hash`
  - `kms_poseidon_hash_many`
  - `kms_generate_mnemonic`
  - `kms_generate_mnemonic_from_entropy`
  - `kms_validate_mnemonic`
  - `kms_mnemonic_to_seed`
  - `kms_derive_private_key_with_coin_type`
  - `kms_derive_keypair_with_coin_type`
  - `kms_derive_view_private_key`
  - `kms_derive_view_keypair`
  - `kms_derive_nostr_private_key`
  - `kms_derive_nostr_keypair`
  - `kms_calculate_contract_address`
  - `kms_derive_oz_account_address`
  - coin type constants + error name/message
- Workstream A modules implemented in Zig:
  - SHA-256/SHA-512/HMAC-SHA512/PBKDF2-HMAC-SHA512
  - BIP-39 (English wordlist) generation/validation/seed
  - BIP-32 secp256k1 derivation (hardened + non-hardened)
  - Stark grinding (`sha256(seed || u8_counter)` rejection sampling)
  - Stark curve public-key derivation
  - Pedersen and Poseidon hash kernels
  - Starknet OZ account-address derivation
- SHE module port completed in Zig:
  - Curve wrappers and scalar arithmetic modulo Stark curve order
  - Fiat-Shamir challenge helpers (Pedersen + Poseidon challenge reduction)
  - PoE and PoE2 protocols
  - ElGamal encryption/proof/verification/decryption
  - Bit proofs and range proofs
  - Audit proof protocol (SameEncryptUnknownRandom)
- TONGO SDK module port completed in Zig:
  - Account model and key helpers (owner + optional view key)
  - ECDH-based audit hint encryption/decryption (`XChaCha20Poly1305`)
  - Operations: `fund`, `transfer`, `rollover`, `withdraw`, `ragequit`
- Nostr messaging module port completed in Zig:
  - secp256k1 ECDH shared-secret derivation
  - public-key derivation (compressed SEC1 hex)
  - NIP-44-style envelope: HKDF-SHA256 + ChaCha20 + HMAC-SHA256 + base64
- Starknet client core module port completed in Zig:
  - selector derivation (`starknet_keccak` masked to 250 bits)
  - cipher/account typed structures + balance decryption helper
  - Cairo serialization helpers for points/proofs/range/audit/call payloads
  - operation calldata builders for approve/fund/transfer/rollover/withdraw/ragequit
  - response-decoding helpers for account state/rate/bit-size/ERC20/auditor-key
  - thin JSON-RPC transport adapter (`callRaw`) with explicit I/O boundary
- Wrapper surfaces expanded and build-verified for:
  - Go (`packages/kms-go`)
  - Rust (`packages/kms-rs`)
  - Python (`packages/kms-py`)
  - Swift (`packages/kms-swift`)
- Header sync automation added:
  - `tools/sync_kms_header.sh`

## Verification Completed

- `zig build --build-file zig/build.zig test`
- `go test ./...` in `packages/kms-go`
- `cargo test -p ghoul-kms`
- `swift build` in `packages/kms-swift` (package has no tests target)
- `python3 -m pytest -q` in `packages/kms-py` (no tests discovered)

## Remaining Work

- Add full cross-language wrapper conformance tests consuming shared vectors.
- Add Rust differential CI job (`tools/rust-oracle`) for randomized parity.
- Implement constant-time leakage harnesses and performance gates for GA.
- Complete release publication workflows for all package registries.
