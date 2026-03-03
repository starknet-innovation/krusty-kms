<p align="center">
  <img src="assets/krusty-crab.png" width="400" alt="Krusty" />
</p>

<h1 align="center">Krusty</h1>

<p align="center">
  Starknet key management, confidential transactions, and protocol client libraries in Rust.
</p>

Krusty provides BIP-39/44 key derivation for Stark and Ethereum curves, zero-knowledge proof generation for the TONGO confidential transaction protocol, and a typed async client for interacting with Starknet contracts — wallets, tokens, staking, and DeFi.

## Crates

```
krusty-kms-common     Shared types: Address, Amount, ChainId, Token, error definitions
krusty-kms-crypto     Cryptographic primitives: ElGamal encryption, Pedersen commitments,
                      range proofs, ZK proof generation and verification
krusty-kms            Key management: BIP-39 mnemonics, BIP-44 HD derivation (Stark +
                      secp256k1), account class abstractions (OZ, Argent, Braavos, OZ Eth)
krusty-kms-sdk        TONGO protocol operations: fund, transfer, withdraw, rollover,
                      ragequit — with dual-key (owner + view) confidential balances
krusty-kms-client     Starknet RPC client: Wallet and EthWallet execution, ERC-20 token
                      interactions, STRK staking delegation, Vesu money market, transaction
                      batching and tracking
krusty-kms-wasm       WebAssembly bindings for browser environments
krusty-kms-cabi       C ABI shared library (libkms)
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
cargo test --workspace              # Run all tests including experimental
cargo clippy --workspace --all-targets
cargo fmt --all
```

### WASM

```bash
cd crates/wasm && wasm-pack build --target web
```

## License

MIT OR Apache-2.0
