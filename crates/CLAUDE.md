# Rust Crates Workspace

Core cryptography and protocol implementation for Krusty KMS.

## Workspace Structure

```
crates/
├── common/                           # Shared types, errors, utilities (package: krusty-kms-common)
├── crypto/                           # Cryptographic primitives and proofs (package: krusty-kms-crypto)
├── kms/                              # Key management and derivation (package: krusty-kms)
├── sdk/                              # Confidential transaction SDK (package: krusty-kms-sdk)
├── client/                           # Starknet RPC client (package: krusty-kms-client)
├── wasm/                             # WASM bindings (package: krusty-kms-wasm)
├── ffi/                              # C ABI shared library (package: krusty-kms-cabi)
└── experimental/                     # Not part of default workspace builds
    └── gaming-experimental/
        ├── mental-poker/
        ├── mental-poker-wasm/
        └── qb-game/
```

## Production Dependency Graph

```
krusty-kms-common
    ↓
krusty-kms-crypto
    ↓
krusty-kms
    ↓
krusty-kms-sdk
    ↓
├── krusty-kms-wasm
└── krusty-kms-client
```

## Quick Commands

```bash
# From repo root
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test            # default-members: production crates only
cargo test --workspace

# WASM builds (production)
cd crates/wasm && wasm-pack build --target web

# Experimental crates (run explicitly)
cargo test -p mental-poker
cargo test -p qb-game
```

## Crate Domains

### Production core
- `krusty-kms-common`: shared types and utilities.
- `krusty-kms-crypto`: cryptographic primitives and proofs.
- `krusty-kms`: mnemonic/account/key derivation.
- `krusty-kms-sdk`: protocol operations (`fund`, `transfer`, `withdraw`, `rollover`, `ragequit`).
- `krusty-kms-client`: Starknet RPC adapter and contract-facing calls.

### Production WASM
- `krusty-kms-wasm`: browser-safe builds use `default-features = false` for threaded dependencies.

### FFI
- `krusty-kms-cabi`: C ABI shared library (`libkms.dylib`).

### Experimental
- `experimental/gaming-experimental/*`: game protocol experiments, non-default.

## Testing Notes

- Keep tests deterministic (fixed seeds, no hidden network dependency).
- Bug fixes require regression tests.
- New abstractions should include law/property tests where feasible.
