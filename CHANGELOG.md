# Changelog

All notable changes to the published Rust crates are documented here.

## [Unreleased]

## [0.7.0] - 2026-08-10

### Changed

- **Breaking:** NATS multisig coordination is now opt-in through the
  `krusty-kms-client/nats` feature, removing its dependency subtree from the
  default client graph.
- Deduplicated Starknet signing onto Software Mansion's
  `starknet-rust-crypto` package and removed unused direct, test-only, and WASM
  dependencies across the workspace.
- Removed the archived `console_error_panic_hook` from the WASM packages.

## [0.6.1] - 2026-08-10

### Changed

- Internal refactor only: split oversized source files into focused modules
  (`gateway` runtime, `client` multisig, `domain`, `oracle`, `wasm`
  account/signing, `kms` discovery, `crypto` ElGamal tests) per the PR #45
  review follow-up (#51). No public API or behavior changes; all crate-root
  paths are preserved via re-exports.

## [0.6.0] - 2026-08-10

### Changed

- **Breaking:** `stark_public_key` now returns `Result` and rejects zero or
  out-of-range Stark private keys via `validate_stark_private_key` (H-08),
  propagated through the WASM exports.
- **Breaking:** `Multisig::new` takes the expected `ChainId`, and
  `MultisigProposal` carries a `chain_id`; `confirm_proposal` rejects
  proposals and wallets bound to any other chain before signing (H-02
  follow-up).
- ElGamal: new `encrypt_strong`/`verify_strong` whose Fiat-Shamir challenge
  `H(prefix, pk, L, R, AL, AR)` additionally binds the public key and the `AR`
  commitment (H-01); legacy `encrypt`/`verify` retained for deployed
  verifiers. New `kms_elgamal_encrypt_strong` C ABI export, published in the
  C, JVM, Swift, and Dart bindings.
- Gateway operation IDs are random 128-bit hex instead of sequential (H-06),
  and OS-entropy failures now return a retryable `Internal` error instead of
  panicking.

### Fixed

- Gateway wait loops: deadline arithmetic no longer overflows, per-poll sleeps
  are capped at the remaining deadline, and `timeout_ms`/`poll_interval_ms`
  are bounded by `MAX_WAIT_TIMEOUT_MS` (H-04).
- Snapshot cache policies clamp caller-provided `ttl_ms` and
  `stale_while_revalidate_ms` to server-side maximums (H-05).
- Multisig coordination: receive-side validation of coordinator messages
  (topic consistency, proposal transaction-id integrity) in the NATS and HTTP
  coordinators (H-02).
- FFI/JNI/Swift secret hygiene: `Zeroizing`/`SecretFelt` wrap mnemonics,
  seeds, derived keys, and ElGamal scalars across the FFI surface (H-11);
  binding-side copies are wiped with `memset_s`/`explicit_bzero` (H-12);
  Swift `ethSign` rejects non-32-byte keys (H-09); JNI array conversions
  validate null/length and guard allocation-size overflow (H-13).
- Trust-model documentation for `SecretResolver`, `SecretRef`, and
  `StdioOracle` (C-01).

## [0.5.4] - 2026-08-10

### Changed

- crates.io publishing now uses GitHub Actions OIDC trusted publishing.
