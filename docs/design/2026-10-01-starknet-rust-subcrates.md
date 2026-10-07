# Depend on starknet-rust sub-crates, not the umbrella

Date: 2026-10-01. Updated: 2026-10-07. Status: accepted.
Origin: dependency-count review.

## Problem

`krusty-kms-wallet-api`, `krusty-kms-gateway` and `krusty-kms-client` depend
on `starknet-rust` 0.19.1. That crate has no code of its own. It re-exports six
crates as modules (`core`, `providers`, `accounts`, `signers`, `contract`,
`macros`), and depending on it builds all six.

Krusty uses four of them. The other two cost more than their size suggests:

- `starknet-rust-macros` is a proc-macro that depends on `starknet-rust-core`.
  Proc-macros build for the host, so cargo compiles a second copy of
  `starknet-rust-core`, `starknet-rust-crypto`, `starknet-types-core` and the
  lambdaworks crates under it. No krusty crate calls a `starknet-rust` macro.
- `starknet-rust-contract` (contract factory) is not used either.

`krusty-kms-wallet-api` also uses only `core` and `providers`. Through the
umbrella it still pulled `starknet-rust-signers` → `eth-keystore` 0.5 and the
RustCrypto 0.10 crates listed in `docs/supply-chain.md`.

Separately, `krusty-kms` and `krusty-kms-wasm` depend on `rand` and `rand_core`
for three calls to `rand::rngs::SysRng::try_fill_bytes`.

## Change

| Crate | Before | After |
| --- | --- | --- |
| wallet-api | `starknet-rust` | `starknet-rust-core`, `starknet-rust-providers` |
| gateway, client | `starknet-rust` | `starknet-rust-core`, `-providers`, `-accounts`, `-signers` |
| kms | `rand`, `rand_core` | `getrandom` 0.4 (already in the graph) |
| wasm | `rand`, `rand_core`, `getrandom` | `getrandom` |

The sub-crates and the `starknet-crypto` alias now pin `=0.20.0` together.
Signers disables default features and enables only `std`; Krusty does not use
its Ethereum keystore API. Accounts does not re-enable `keystore`.
Source paths change mechanically: `starknet_rust::core::` becomes
`starknet_rust_core::`, and the same for `providers`, `accounts` and `signers`.

`rand::rngs::SysRng` is `pub use getrandom::SysRng`, and its `try_fill_bytes`
calls `getrandom::fill`. The mnemonic entropy buffer, `randomFelt` and
`randomBytesHex` now call `getrandom::fill` directly. The entropy source and
the failure handling stay the same: `generate_mnemonic` and `randomFelt` panic
when OS entropy fails, and `randomBytesHex` returns an error.

Two dev-only trims ship with this change. They do not touch production
dependencies:

- `criterion` builds without its default features. It keeps
  `cargo_bench_support` and drops `plotters` and `rayon`. Benches print the
  same statistics. Criterion's statistical analysis now runs on one thread,
  and it draws plots only if `gnuplot` is installed. `html_reports` was never
  enabled.
- The `krusty-kms-client` tests enable tokio's `macros`, `rt-multi-thread` and
  `test-util` features instead of `full`. Those are the only features the tests
  use beyond the crate's normal tokio features.

## Interface we keep

The path rename itself preserves the sub-crate types re-exported by the umbrella.
The subsequent 0.20.0 upgrade changes the upstream core, provider, account and
signer types exposed by Krusty's Rust APIs. Consumers passing those types must
also upgrade their starknet-rust dependencies; 0.19.1 provider/account types do
not unify with 0.20.0. `Felt` still comes from starknet-types-core 0.2.4.

Upstream changes include optional legacy ABIs, response IDs, transport error
variants, subscription decoding errors, and corrected Cairo 0 class hashing.
Krusty does not construct legacy ABI/response structs or match subscription errors.
Its two HTTP error classifiers now handle `InvalidNumericResponseId` as `other`
and `BatchError` by numeric JSON-RPC code only. Server messages/data remain
redacted, covered by client and gateway regression tests. Krusty's own keystore
implementation remains available and does not depend on upstream `eth-keystore`.

The client utility file-size baseline grows solely for those error arms and the
redaction regression test; no FFI or WASM surface snapshot changes are needed.

## Measured effect

Original 0.19.1 measurements (2026-10-01), counted with `cargo +nightly build --unit-graph` (compile units, excluding
build-script runs) and lockfile entries:

| Scope | Before | After |
| --- | --- | --- |
| `Cargo.lock` packages | 452 | 440 |
| workspace build, units | 337 | 296 |
| workspace `--all-targets`, units | 443 | 391 |
| `krusty-kms-client`, units / packages | 318 / 248 | 276 / 244 |
| `krusty-kms-gateway`, units / packages | 314 / 245 | 272 / 241 |
| `krusty-kms-wallet-api`, units / packages | 250 / 190 | 197 / 174 |
| `krusty-kms`, packages | 129 | 128 |

The packages that leave the lockfile are `starknet-rust`,
`starknet-rust-contract`, `starknet-rust-macros`, `plotters` (three crates),
and the tokio `full` extras `parking_lot`, `parking_lot_core`, `lock_api`,
`scopeguard`, `signal-hook-registry` and `redox_syscall`. `rand` 0.10 stays in
the lockfile because the experimental gaming crates use it.

Updated 0.20.0 measurements (2026-10-07), with stable Cargo's unit graph
(`RUSTC_BOOTSTRAP=1 cargo build --locked --unit-graph -Z unstable-options`),
excluding build-script runs:

| Scope | Units | Packages in build graph |
| --- | --- | --- |
| workspace build | 283 | — |
| workspace all targets | 378 | 301 |
| client | 263 | 238 |
| gateway | 259 | 234 |
| wallet-api | 205 | 184 |
| kms | 147 | 130 |

The lockfile has 439 packages (440 before this upgrade). Twelve obsolete version
entries leave: eth-keystore 0.5, aes 0.8, cipher 0.4, ctr 0.9, inout 0.1,
scrypt 0.10, salsa20 0.10, pbkdf2 0.11, hmac 0.12, uuid 0.8, thiserror 1 and
thiserror-impl 1. New upstream constraints also resolve additional optional
packages, so the net lockfile reduction is one package. Production workspace
builds drop another 13 compile units, from 296 to 283.

Remove the unmatched keystore-only duplicate allowances and hmac 0.12.
Retain crypto-common 0.1 and the remaining RustCrypto 0.10 allowances still
needed by lambdaworks, blake2 and async-nats; replace rfc6979 0.4 with the
upstream-required 0.5 allowance (Krusty's k256 still requires 0.6).

## Not done

- **Trim `k256` features** (drop `pkcs8`). This saves one crate and changes
  the feature set of a signing dependency. Not worth it here.
- **Move krusty to `num-bigint` 0.4** to share lambdaworks' copy. This saves one
  crate but goes back a major version. Better to wait for lambdaworks to move.
- **Enable `starknet-types-core/hash` only where hashing is used.** `common` and
  `domain` would get lighter on their own, but every published consumer
  enables it through `kms`, so nothing downstream changes.
