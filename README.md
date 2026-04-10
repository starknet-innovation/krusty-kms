<p align="center">
  <img src="assets/krusty-crab.png" width="400" alt="Krusty" />
</p>

<h1 align="center">Krusty</h1>

<p align="center">
  Deterministic key management, Starknet account tooling, and protocol cryptography in Rust.
</p>

> **Disclaimer**: This repository is experimental and is provided strictly for testing and experimentation purposes. It should not be used in production environments or relied upon for any security-critical application. There are no guarantees of stability, correctness, or continued maintenance. Use at your own risk.

Krusty provides BIP-39/44 key derivation for Starknet and Nostr domains, deterministic Stark and Nostr signing, OpenZeppelin account descriptor/address calculation, Tongo confidential proof generation, and a focused Starknet client/gateway surface.

## Published Crates

```
krusty-kms-common     Shared value types, errors, and exact serialization helpers
krusty-kms-wallet-api Shared wallet execution contract: transaction tracking, wait options,
                      and the minimal WalletExecutor boundary shared by wallet crates
krusty-kms-domain     Pure typed integration contracts for gateway/client orchestration
krusty-kms-gateway    Long-lived runtime for derive/check/deploy/sign/query flows with
                      explicit secret, cache, and RPC boundaries
krusty-kms-crypto     Cryptographic primitives and zero-knowledge proofs
krusty-kms            Deterministic derivation, account descriptors, and Stark/Nostr signing
krusty-kms-sdk        Tongo protocol operations: fund, transfer, withdraw, rollover,
                      ragequit for confidential balances
krusty-kms-client     Focused Starknet wallet, deployment, Tongo account, and call-builder client
```

## Internal Crates

These remain in the repository for internal, experimental, or integration-specific use:

```
krusty-kms-oracle     Versioned stdio transport on top of the gateway
krusty-kms-wasm       WebAssembly bindings for browser environments
krusty-kms-controller Cartridge Controller integration
krusty-kms-cabi       C ABI shared library (libkms)
mental-poker*         Experimental gaming protocol crates
qb-game               Experimental game crate
```

## Language Bindings

| Package | Language | Method |
|---------|----------|--------|
| `packages/kms-swift` | Swift | SwiftPM via C FFI |
| `packages/kms-jvm` | Java/Kotlin | JNI |
| `packages/kms-dart` | Dart | dart:ffi |
| `packages/kms-c` | C | Header distribution |

## Quick Start

```bash
cargo test                          # Run default-member tests
cargo test --workspace              # Run all workspace tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
wasm-pack test --node crates/wasm   # Run the JS/WASM boundary tests
```

## Examples

Examples live in:

```text
crates/kms/examples/key_derivation.rs
crates/kms/examples/stark_sign.rs
crates/kms/examples/nostr_sign.rs
crates/kms/examples/oz_address.rs
crates/sdk/examples/tongo_proof_generation.rs
```

### WASM

```bash
cd crates/wasm && wasm-pack build --target web
```

## License

MIT OR Apache-2.0
