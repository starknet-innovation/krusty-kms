# Clear the crypto-bigint, ctutils, and tokio advisories

Date: 2026-10-28. Status: accepted. Origin: `cargo-deny` failure on main and on
PR 182.

## Problem

`cargo deny check` fails its advisories gate on the locked graph:

| Advisory | Locked crate | Failure |
| --- | --- | --- |
| RUSTSEC-2026-0387 | `crypto-bigint` 0.7.5 | timing variability in operations meant to be constant-time; also yanked |
| RUSTSEC-2026-0385 | `ctutils` 0.4.2 | non-constant-time mask generation and `u128` comparisons |
| RUSTSEC-2026-0386 | `tokio` 1.50.0 | `AsyncFd::new` and related constructors are unsound |

`crypto-bigint` is the direct dependency behind scalar arithmetic in
`krusty-kms-crypto` (`ConstMontyForm` modulo the Stark curve order) and a
transitive dependency of `k256` / `elliptic-curve` and `starknet-rust`.
`ctutils` is transitive, including through `crypto-bigint` and `digest`.
`tokio` 1.50.0 is the single async runtime, reached from `krusty-kms-client`,
`reqwest`, and `async-nats`.

## Contract

No public signature changes. Scalar arithmetic still goes through
`ConstMontyForm<CurveOrder, { U256::LIMBS }>` and still returns `Felt`.

The workspace floors move to versions `cargo-deny` accepts:

- `crypto-bigint` `0.7.10` (caret). RustSec's patched range starts at 0.7.6,
  but 0.7.6, 0.7.7, and 0.7.8 are yanked because 0.7.9 changed the blanket
  `Mul` impl for `NonZero<T>`. 0.7.9 and 0.7.10 are the non-yanked releases;
  0.7.10 is the current one and requires `ctutils` `^0.4.6`. Its MSRV is
  1.87, inside this workspace's 1.92 floor. Scalar code multiplies
  `ConstMontyForm` residues; the 0.7.9 break is the blanket `Mul` impl for
  `NonZero<T>`.
- `ctutils` `0.4.6`, pulled by that `crypto-bigint` requirement and allowed
  by every other `^0.4` edge (`digest` 0.11). RustSec is patched from 0.4.4.
- `tokio` `1.54.1` (caret). RustSec is patched on `>= 1.51.6, < 1.52.0` or
  `>= 1.53.3`. 1.54.1 is the latest release on the second range. The same
  update moves `libc` to 0.2.191, `mio` to 1.2.4, `socket2` to 0.6.5, and
  `tokio-macros` to 2.7.2, and drops `windows-sys` 0.60.2, which nothing else
  in the lockfile referenced. One `tokio` remains.

`krusty-kms-controller` stays on its own `tokio` `1.43.0` requirement. That
crate is workspace-excluded and outside the `cargo-deny` graph; a fresh
resolve of `^1.43.0` still selects 1.54.1.

## Laws

1. `cargo deny check` reports advisories, bans, licenses, and sources ok.
   The locked `crypto-bigint` is not yanked.
2. The lockfile contains one `crypto-bigint`, one `ctutils`, and one `tokio`.
3. `scalar_add`, `scalar_sub`, `scalar_mul`, and `reduce_scalar` keep their
   current results, including wraparound modulo the curve order.
