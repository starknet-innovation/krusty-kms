# Depend on starknet-rust sub-crates, not the umbrella

Date: 2026-10-01. Status: accepted. Origin: dependency-count review.

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

All of them stay pinned at `=0.19.1`, the version the umbrella resolved to.
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

The public API is unchanged. Every `starknet_rust::X` path is a `pub use` of
the sub-crate type, so signatures that expose `Felt`, `JsonRpcClient`,
`SingleOwnerAccount`, `LocalWallet` or `ProviderError` name the same types.
Downstream crates that also depend on `starknet-rust` 0.19.1 still unify with
them.

## Measured effect

Counted with `cargo +nightly build --unit-graph` (compile units, excluding
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

No `deny.toml` skip changes. `eth-keystore` and its RustCrypto 0.10 crates are
still reached through `starknet-rust-signers`, which gateway and client need.

## Not done

- **Drop `eth-keystore`.** `starknet-rust-signers` depends on it on every
  non-wasm target with no feature gate.
  [software-mansion/starknet-rust#170](https://github.com/software-mansion/starknet-rust/pull/170)
  proposes a default-on `keystore` feature for it. Once that ships, gateway and
  client can depend on signers with `default-features = false, features =
  ["std"]`. That drops 12 crates and the matching `deny.toml` skips.
- **Trim `k256` features** (drop `pkcs8`). This saves one crate and changes
  the feature set of a signing dependency. Not worth it here.
- **Move krusty to `num-bigint` 0.4** to share lambdaworks' copy. This saves one
  crate but goes back a major version. Better to wait for lambdaworks to move.
- **Enable `starknet-types-core/hash` only where hashing is used.** `common` and
  `domain` would get lighter on their own, but every published consumer
  enables it through `kms`, so nothing downstream changes.
