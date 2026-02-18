# KMS Zig Workspace

Zero-external-dependency Zig replatform for KMS cryptography and Starknet-core
types.

## Goals

- Zig-first architecture (not a line-by-line Rust translation).
- Deterministic behavior and explicit error contracts.
- No external Zig package dependencies.

## Commands

```bash
zig build --build-file zig/build.zig
zig build --build-file zig/build.zig test
```

## Current Status

- Module boundaries and compile/test scaffolding are implemented.
- Stable C ABI header implemented at `zig/include/kms.h`.
- Native static + shared library artifacts are produced by `build.zig`.
- Core integer/field math, Stark curve ops, Pedersen, Poseidon, BIP-39, BIP-32,
  grinding, derivation, and account-address derivation are implemented.
- Zig unit tests include Rust parity vectors for seed derivation, coin-key
  derivation, Nostr key derivation, and OZ account address derivation.
