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

## Alternatives considered

- Hard-fail every file over 350 lines immediately — rejected; too much churn.
- Policy-only docs — rejected; already proven insufficient.
