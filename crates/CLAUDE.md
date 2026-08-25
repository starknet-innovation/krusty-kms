# Rust Crates Workspace

Core cryptography and protocol implementation for Krusty KMS.

## Workspace Structure

```
crates/
├── common/                           # Shared types, errors, utilities (package: krusty-kms-common)
├── wallet-api/                       # Wallet execution interfaces (package: krusty-kms-wallet-api)
├── domain/                           # Pure gateway/client contracts (package: krusty-kms-domain)
├── crypto/                           # Cryptographic primitives and proofs (package: krusty-kms-crypto)
├── kms/                              # Key management and derivation (package: krusty-kms)
├── sdk/                              # Confidential transaction SDK (package: krusty-kms-sdk)
├── client/                           # Starknet RPC client (package: krusty-kms-client)
├── gateway/                          # Long-lived application runtime (package: krusty-kms-gateway)
├── oracle/                           # Versioned stdio adapter (package: krusty-kms-oracle)
├── wasm/                             # WASM bindings (package: krusty-kms-wasm)
├── ffi/                              # C ABI shared library (package: krusty-kms-cabi)
├── controller/                       # Cartridge adapter, excluded from the workspace
└── experimental/                     # Not part of default workspace builds
    └── gaming-experimental/
        ├── mental-poker/
        ├── mental-poker-wasm/
        └── qb-game/
```

## Production Dependency Graph

```
common ──► wallet-api ───────────────────────────────► client
   ├────► domain ──► gateway ──► oracle
   └────► crypto ──► kms ──► sdk ──┬───────────────► client
                            ├───────┼───────────────► wasm
                            └───────┴───────────────► ffi
```

This is an orientation map, not the enforcement source. See
`.github/scripts/check-dependency-layers.sh` for the complete allowed edge set.

## Quick Commands

```bash
# From repo root
bash tools/check.sh quick
bash tools/check.sh rust
bash tools/check.sh all

# WASM boundary tests (production)
bash tools/check.sh wasm

# Experimental crates (run explicitly)
cargo test -p mental-poker
cargo test -p qb-game
```

## Crate Domains

### Production core
- `krusty-kms-common`: shared types and utilities.
- `krusty-kms-wallet-api`: shared wallet execution and transaction tracking contracts.
- `krusty-kms-domain`: pure typed contracts for gateway/client orchestration.
- `krusty-kms-crypto`: cryptographic primitives and proofs.
- `krusty-kms`: mnemonic/account/key derivation.
- `krusty-kms-sdk`: protocol operations (`fund`, `transfer`, `withdraw`, `rollover`, `ragequit`).
- `krusty-kms-client`: Starknet RPC adapter and contract-facing calls.
- `krusty-kms-gateway`: stateful runtime with explicit secret, cache, and RPC boundaries.

### Runtime adapters
- `krusty-kms-oracle`: versioned stdio transport over the gateway; not published.
- `krusty-kms-controller`: Cartridge adapter; excluded from the workspace.

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
