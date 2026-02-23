# KMS Crates Monorepo

Rust crates for Starknet-curve key management, cryptography, protocol operations, and WASM bindings.

## Directory Structure

```
crates/
├── common/                           # Shared types, errors, utilities (krusty-kms-common)
├── crypto/                           # Cryptographic primitives and proofs (krusty-kms-crypto)
├── kms/                              # Key management and derivation (krusty-kms)
├── sdk/                              # Confidential transaction SDK (krusty-kms-sdk)
├── client/                           # Starknet RPC client (krusty-kms-client)
├── wasm/                             # WASM bindings (krusty-kms-wasm)
├── ffi/                              # C ABI shared library (krusty-kms-cabi)
└── experimental/                     # Non-default and in-progress work
    └── gaming-experimental/

packages/
├── kms-c/                            # C ABI header distribution
├── kms-ts/                           # TypeScript wrapper (native + wasm entrypoints)
├── kms-swift/                        # SwiftPM wrapper
├── kms-go/                           # Go cgo wrapper
├── kms-rs/                           # Rust FFI wrapper
├── kms-py/                           # Python ctypes wrapper
└── kms-jvm/                          # Shared JNI package (Java + Kotlin)

fixtures/vectors/                     # Shared cross-language conformance vectors
tools/                                # Build/release helpers
```

## Active (Default) Crates

- `crates/common` (krusty-kms-common)
- `crates/crypto` (krusty-kms-crypto)
- `crates/kms` (krusty-kms)
- `crates/sdk` (krusty-kms-sdk)
- `crates/client` (krusty-kms-client)
- `crates/wasm` (krusty-kms-wasm)

## Experimental (Non-default) Crates

- `crates/experimental/gaming-experimental/mental-poker`
- `crates/experimental/gaming-experimental/mental-poker-wasm`
- `crates/experimental/gaming-experimental/qb-game`

## Wrapper Verification

- TypeScript: `npm --prefix packages/kms-ts run typecheck`
- Swift: `cd packages/kms-swift && swift build`
- Go: `cd packages/kms-go && go test ./...`
- Rust: `cargo check -p krusty-kms-ffi`
- Python: `python3 -m compileall -q packages/kms-py/src`
