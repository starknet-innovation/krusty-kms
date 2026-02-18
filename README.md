# KMS Crates Monorepo

Rust crates for Starknet-curve key management, cryptography, protocol operations, and WASM bindings.

## Directory Structure

```
crates/
├── core/                             # Production Rust crates
├── wasm/                             # Production WASM bindings
└── experimental/                     # Non-default and in-progress work
    ├── post-quantum/
    └── gaming-experimental/

zig/
├── src/                              # Zig-first replatform modules
└── build.zig                         # Zig build entrypoint

packages/
├── kms-c/                            # C ABI header distribution
├── kms-ts/                           # TypeScript wrapper (native + wasm entrypoints)
├── kms-swift/                        # SwiftPM wrapper
├── kms-go/                           # Go cgo wrapper
├── kms-rs/                           # Rust FFI wrapper
├── kms-py/                           # Python ctypes wrapper
└── kms-jvm/                          # Shared JNI package (Java + Kotlin)

fixtures/vectors/                     # Shared cross-language conformance vectors
tools/                                # Rust oracle + build/release helpers
```

## Active (Default) Crates

- `crates/core/common`
- `crates/core/she-core`
- `crates/core/kms`
- `crates/core/tongo-sdk`
- `crates/core/nostr-messaging`
- `crates/core/starknet-client`
- `crates/wasm/she-core-wasm`
- `crates/wasm/kms-wasm`
- `crates/wasm/tongo-wasm`
- `crates/wasm/nostr-wasm`

## Experimental (Non-default) Crates

- `crates/experimental/post-quantum/candyland-wasm` (WASM package artifacts)
- `crates/experimental/gaming-experimental/mental-poker`
- `crates/experimental/gaming-experimental/mental-poker-wasm`
- `crates/experimental/gaming-experimental/qb-game`

## Zig Replatform

- Foundation workspace: `zig/`
- Design note: `docs/design/2026-02-13-zig-replatform-foundation.md`
- v1 status tracker: `docs/zig-kms-v1-status.md`
- Commands:
  - `zig build --build-file zig/build.zig`
  - `zig build --build-file zig/build.zig test`
  - `./tools/sync_kms_header.sh`

## Wrapper Verification

- TypeScript: `npm --prefix packages/kms-ts run typecheck`
- Swift: `cd packages/kms-swift && swift build`
- Go: `cd packages/kms-go && go test ./...`
- Rust: `cargo check -p ghoul-kms`
- Python: `python3 -m compileall -q packages/kms-py/src`
