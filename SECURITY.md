# Security Policy

## Supported versions

This repository is experimental. Security fixes are applied on a best-effort
basis to the latest published crates.io versions on `main`. Older versions may
not receive patches.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report suspected vulnerabilities privately to the maintainers:

- Email: **security@starknet.org** (and/or the repository owner listed in the
  GitHub security advisories UI)
- Prefer GitHub **Private vulnerability reporting** on this repository when
  enabled: *Security → Report a vulnerability*

Include:

1. A clear description of the issue and impact (key leakage, signature forgery,
   proof soundness, ABI memory safety, etc.).
2. Affected crate(s) and versions.
3. Steps to reproduce or a proof-of-concept (non-destructive).
4. Any suggested fix, if you have one.

We will acknowledge receipt as soon as practical and coordinate disclosure.

## Security-sensitive areas

Treat changes in these areas with extra scrutiny:

- Key derivation, mnemonics, keystore encryption (`krusty-kms`)
- Secret wrappers (`SecretFelt`) and any `expose_secret*` call sites
- Proof generation / verification (`krusty-kms-crypto`, `krusty-kms-sdk`)
- FFI and WASM boundaries (`krusty-kms-cabi`, `krusty-kms-wasm`)
- Transaction hashing and typed-data hashing

## Maintainer expectations

- Never log or `Display` raw secret key material.
- Prefer `SecretFelt` / `zeroize` for secret scalars.
- Production crates declare `#![forbid(unsafe_code)]` (or a narrow
  `deny`/`allow` exception for `SecretFelt` / the C ABI crate). Expanding those
  exceptions requires a `docs/design/*.md` note for baseline/surface changes —
  a PR-body `## Design` heading alone is not enough for FFI/WASM/file-size
  baseline updates.
- Dependency advisories are gated by `cargo audit` (`rust.yml`) and
  `cargo-deny` (`guardrails.yml`).
