# Design: maintainability guardrails

Date: 2026-08-10

## Problem

`CONTRIBUTING.md` already encodes strong maintainability constraints (file/PR
size, information hiding, design notes, secret handling), but most of those
rules were social only. Oversized production files already exceed the documented
limits, Dependabot was misconfigured, and public/FFI/WASM surfaces could drift
without CI noticing.

## Goals

- Turn the highest-signal CONTRIBUTING rules into **executable fitness checks**.
- Ratchet existing debt (do not force a mega-split PR up front).
- Protect publishable crate semver, docs links, dependency DAG, and ABI/WASM
  surfaces.
- Keep the lint policy small and high-signal.

## Non-goals

- Mass-splitting every oversized file in this change.
- Enabling `#![deny(missing_docs)]` workspace-wide before coverage is ready.
- Expanding Clippy into pedantic/nursery denials.

## Design

New CI workflow `.github/workflows/guardrails.yml` runs:

1. **File-size ratchet** against `.github/guardrails/file-size-baseline.json`
2. **PR size** soft gate with an explicit justification marker escape hatch
3. **Dependency layering** for `krusty-*` edges
4. **`unsafe` allowlist**
5. **Secret hygiene** smoke checks around `SecretFelt`
6. **FFI / WASM surface snapshots**
7. **Design-note requirement** when public surface / deps / snapshots change
8. **`cargo-deny`**, **rustdoc link checks**, **`cargo-semver-checks`**

Baselines are regenerated with
`.github/scripts/regenerate-guardrail-baselines.sh`.

Ignored integration tests get a weekly compile + `workflow_dispatch` runner so
`--ignored` harnesses do not silently bitrot.

## Failure modes

- Intentional ABI/API growth must update snapshots and include a design note.
- Semver-checks fails when crates.io baseline is incompatible; fix by versioning
  correctly or adjusting the public API.
- `cargo-deny` may need license allowlist updates when adding dependencies.

## Review follow-ups (2026-08-10)

Addressed on the same PR after review:

- Reverted exact `starknet-types-core` pin; rely on lockfile + locked rustdoc JSON.
- Replaced textual `unsafe` allowlist with crate-level `forbid`/`deny`/`allow`.
- Layering check fails closed on unknown crates (incl. `controller` + experimental).
- Guardrails `push` limited to `main` + concurrency group; prebuilt tool installs.
- Design-note coverage widened; baseline bumps require `docs/design/*.md`.
- PR-size / design-note fail closed on PRs; shared `surfaces.py` for extractors.
- Softened `SECURITY.md`; dropped redundant FFI digest; trimmed deny licenses.
- Public/WASM fingerprints keep API-bearing attrs (`cfg`/`derive`/`serde`/`repr`/
  `non_exhaustive`), including field-level `#[serde(...)]`; WASM snapshot refreshed
  accordingly. FFI freeze also compares Dart `lookupFunction` bindings to `kms.h`.
- Fingerprints collect multiline field types and prefix items with inline `mod`
  paths; guardrails path filters include `packages/kms-dart/**`.
- FFI freeze also compares Rust `#[repr(C)]` / `Kms*` type-alias layouts and Dart
  `Struct` layouts to the matching `typedef`s in `kms.h` (field order and types).
- Unsafe policy discovers `crates/*/src/lib.rs` roots (excluding experimental)
  instead of a fixed list, so new crates must declare `unsafe_code` up front.
- FFI/WASM extractors keep preceding `cfg` (and other API-bearing attrs) in
  fingerprints; fitness runs `python3 .github/scripts/lib/surfaces.py` self-checks.
- Swift `kms.h` compare is order-preserving; `self::`/`super::` pub-use paths
  resolve without double-prepending the module path.

