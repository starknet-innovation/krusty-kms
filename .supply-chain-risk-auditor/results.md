# Supply Chain Risk Report

---

## Metadata

- **Scan Date**: 2026-08-10 16:01:40 CEST
- **Project**: krusty-kms
- **Repositories Scanned**: 36 direct-dependency repositories
- **Total Dependencies**: pre-change: 43 direct third-party packages and 409 resolved external packages; post-change: 40 direct packages, 372 default-feature resolved packages, and 406 all-feature resolved packages
- **Scan Duration**: approximately 20 minutes

---

## Executive Summary

This change applies the highest-confidence reductions. NATS coordination is now opt-in because `async-nats` is used only by `NatsMultisigCoordinator`; the legacy `starknet-crypto` package is replaced by Software Mansion's API-compatible successor; the archived `console_error_panic_hook` is removed; and roughly 30 unused or test-only direct dependency edges are removed or reclassified.

Together these changes reduce the default-feature external graph from 409 to 372 packages. Three packages (`console_error_panic_hook`, `starknet-crypto`, and `starknet-curve`) leave the all-feature graph entirely; the NATS subtree remains available only when consumers enable `krusty-kms-client/nats`.

Most unused direct edges do not remove a package from the workspace lockfile because another crate still needs that package. They still reduce each published crate's direct trust and feature surface. The repository metadata check found no repository-local security policy exposed through GitHub's Community Profile API for any of the 36 repositories; organization-level reporting channels may exist and should be checked before treating this as a confirmed absence of a security contact.

### Counts by Risk Factor

| Risk Factor | Dependencies | Total |
|-------------|--------------|-------|
| Archived or stale repository | `console_error_panic_hook`, `bs58`, `subtle` | 3 |
| Low repository popularity relative to this dependency set | `bs58`, `console_error_panic_hook`, `starknet-crypto`, `starknet-rust`, `starknet-types-core` | 5 |
| Strong maintainer concentration | `async-trait`, `bs58`, `hex`, `reqwest`, `serde-wasm-bindgen`, `starknet-crypto`, `thiserror` | 7 |
| High-risk network, deserialization, FFI, or cryptographic boundary | `async-nats`, `reqwest`, `serde`, `serde_json`, `serde-wasm-bindgen`, `starknet-crypto`, `subtle`, `wasm-bindgen` | 8 |
| No repository-local security policy surfaced by GitHub | All 36 repositories scanned | 36 |
| **Total** | Repositories with at least one signal | **36** |

### High-Risk Dependencies

The following pre-change dependencies have two or more risk factors.

| Dependency Name | Risk Factors | Notes | Suggested Alternative |
|-----------------|--------------|-------|-----------------------|
| `console_error_panic_hook` | Archived, stale, low popularity, no repository-local security policy | The repository is archived and its last code push was in 2022. It is used only to improve browser panic messages. | **Remove it** - rely on normal WASM errors in production and add a small local debug-only panic hook only if browser debugging materially needs one. |
| `starknet-crypto` | Maintainer concentration, low popularity, cryptographic boundary, no repository-local security policy | The workspace already resolves Software Mansion's successor through `starknet-rust`; the FFI crate's direct edge is unused. | **`starknet-rust-crypto` 0.9** - alias it as `starknet-crypto` to preserve imports. Its ECDSA implementation is API-compatible here and avoids the duplicate legacy `starknet-curve` package. |
| `bs58` | Stale, low popularity, maintainer concentration, no repository-local security policy | Only the client address codec uses it. The code is small, but replacing an encoding primitive locally creates correctness risk. | **Retain and pin for now** - a small audited local Base58 codec is possible, but is not as cheap or safe as the other removals. |
| `serde-wasm-bindgen` | Maintainer concentration, deserialization boundary, no repository-local security policy | It is actively used at the JS/WASM boundary, so removal would require changing the public conversion path. | **Retain** - `serde_json` through strings is a possible alternative but usually increases allocations and interface complexity. |
| `subtle` | Stale code history, low popularity, cryptographic boundary, no repository-local security policy | It is a de facto constant-time primitive and remains transitively/directly important to the cryptographic crates. | **Retain and audit/pin** - no clearly safer drop-in replacement was identified. |

## Suggested Alternatives

Actions applied in this change:

1. **Feature-gated `async-nats`.** `async-nats` and `bytes` are behind a non-default `nats` feature; `NatsMultisigCoordinator`, its re-export, example, and ignored integration test are gated with it.
2. **Deduplicated Starknet crypto.** The unused FFI edge is removed and KMS aliases `starknet-rust-crypto 0.9` as `starknet-crypto`, preserving source imports while removing `starknet-crypto 0.8.1` and `starknet-curve 0.6.0` from the all-feature graph.
3. **Removed `console_error_panic_hook`.** The optional dependency, default feature, initialization calls, and stale build metadata are gone from both WASM packages.
4. **Cleaned the WASM manifests.** `web-sys` and `wasm-bindgen-futures` are removed from both WASM crates; `thiserror` is removed from the main WASM crate, while `js-sys` and `hex` are removed from `mental-poker-wasm`.
5. **Removed or reclassified unused edges.** Rust's `unused_crate_dependencies` lint plus source-reference checks identified and this change applies:
   - `common`: remove `num-bigint`, `num-traits`, and unused dev dependency `proptest`.
   - `crypto`: remove `num-integer`, `hex`, `sha3`, `thiserror`, and unused dev dependency `proptest`; move `serde`/`serde_json` to dev dependencies; make `sha2` optional under `test-utils`.
   - `kms`: remove `thiserror` and redundant dev re-declarations of `serde`/`serde_json`.
   - `ffi`: remove the unused direct `starknet-crypto` edge.
   - `sdk`: remove `hex`, `rand`, and `thiserror`; move `serde`/`serde_json` to dev-only.
   - `domain`: move `serde_json` to dev-only.
   - `client`: remove `thiserror`.
   - `mental-poker`: remove `num-bigint`, `num-traits`, `rand_core`, `serde_json`, and `sha3`.
   - `qb-game`: remove `krusty-kms-common`, `rand_core`, `starknet-types-core`, `thiserror`, and unused dev dependency `proptest`; move `serde_json` to dev-only.

The WASM-only `getrandom` feature-enabler edges remain in place. They are not source imports, but they activate browser entropy support across transitive versions; consolidating them should be a separate change validated against every WASM package.

Removing Criterion would eliminate another 18 external dev-only packages, but it would also discard the existing benchmark suite; that is not recommended as a cheap security win unless those benchmarks are intentionally retired.

## Report Generated By

Supply Chain Risk Auditor Skill
Generated: 2026-08-10 16:01:40 CEST
