# Rust Crates Workspace

Core cryptography and protocol implementation for GHOUL/TONGO.

## Workspace Structure

```
crates/
├── core/                             # Production Rust crates
│   ├── common/                       # Shared types, errors, utilities (package: ghoul-common)
│   ├── she-core/                     # SHE crypto primitives
│   ├── kms/                          # Key management and derivation
│   ├── tongo-sdk/                    # Confidential transaction operations
│   ├── nostr-messaging/              # Nostr messaging primitives
│   └── starknet-client/              # Starknet RPC integration
├── wasm/                             # Production WASM bindings
│   ├── she-core-wasm/
│   ├── kms-wasm/
│   ├── tongo-wasm/
│   └── nostr-wasm/
└── experimental/                     # Not part of default workspace builds
    ├── post-quantum/
    │   └── candyland-wasm/
    └── gaming-experimental/
        ├── mental-poker/
        ├── mental-poker-wasm/
        └── qb-game/
```

## Production Dependency Graph

```
ghoul-common
    ↓
she-core
    ↓
kms
    ↓
tongo-sdk
    ↓
├── tongo-wasm
└── starknet-client

nostr-messaging
    ↓
nostr-wasm

she-core → she-core-wasm
kms      → kms-wasm
```

## Quick Commands

```bash
# From repo root
cargo fmt --all
cargo clippy --workspace --all-targets
cargo test            # default-members: production crates only
cargo test --workspace

# WASM builds (production)
cd crates/wasm/tongo-wasm && wasm-pack build --target web
cd crates/wasm/kms-wasm && wasm-pack build --target web

# Experimental crates (run explicitly)
cargo test -p mental-poker
cargo test -p qb-game
```

## Crate Domains

### Production core
- `ghoul-common`: shared types and utilities.
- `she-core`: cryptographic primitives and proofs.
- `kms`: mnemonic/account/key derivation.
- `tongo-sdk`: protocol operations (`fund`, `transfer`, `withdraw`, `rollover`, `ragequit`).
- `nostr-messaging`: Nostr private messaging primitives.
- `starknet-client`: Starknet RPC adapter and contract-facing calls.

### Production WASM
- `she-core-wasm`, `kms-wasm`, `tongo-wasm`, `nostr-wasm`.
- Browser-safe builds use `default-features = false` for threaded dependencies.

### Experimental
- `experimental/post-quantum/*`: post-quantum package(s), non-default.
- `experimental/gaming-experimental/*`: game protocol experiments, non-default.

## Testing Notes

- Keep tests deterministic (fixed seeds, no hidden network dependency).
- Bug fixes require regression tests.
- New abstractions should include law/property tests where feasible.
