# Zig Replatform Foundation (Zero-Dependency)

Date: 2026-02-13
Status: Proposed and scaffolded
Owner: KMS core team

## Context

We are replatforming the current Rust cryptography/KMS stack to Zig.
This is not a semantic one-to-one translation. The goal is a Zig-first
architecture that uses Zig language features directly and avoids external
package dependencies.

Reference inspirations:
- `evmts/voltaire` build/module organization:
  https://github.com/evmts/voltaire
- `starknet-io/types-rs` as functional scope reference for Starknet core types:
  https://github.com/starknet-io/types-rs

## Problem Statement

The Rust workspace currently relies on multiple crates and transitive
dependencies for field/curve/hash primitives and protocol-level logic.
We need:
1. A zero-external-dependency Zig codebase.
2. A stable, minimal API surface for callers.
3. Deterministic, testable boundaries so we can migrate in phases.

## Scope

### In scope

- Create a Zig workspace with explicit module boundaries:
  - `core` (felt/u256/curve representations and invariants)
  - `crypto` (hashes and primitives used by higher layers)
  - `kms` (BIP-44 path/domain logic)
  - `she` and `tongo` integration surfaces
- Define stable API contracts before cryptographic implementation.
- Implement deterministic foundational parsing and validation primitives.

### Out of scope (initial phase)

- Full cryptographic equivalence in one step.
- Runtime FFI bridge to Rust for production behavior.
- Dependency on external Zig packages.

## Design Constraints

1. Zero external dependencies:
   - No `build.zig.zon` dependencies.
   - Standard library only (`std`).
2. Deterministic behavior:
   - No hidden I/O, clocks, network calls, or random global state in core logic.
3. Minimal exported interfaces:
   - Keep types/functions small and explicit.
4. Backward compatibility strategy:
   - Port APIs in semantic layers, not by file mirroring.

## Public API (Phase 0-1)

Inputs/outputs and invariants are explicit:

- `core.U256.fromHex(hex)` -> `!U256`
  - Input: `0x` optional hex, up to 64 hex chars.
  - Output: big-endian 32-byte integer.
  - Invariant: canonical 32-byte representation.
  - Failure: `error.InvalidHex`, `error.Overflow`.

- `core.Felt.fromHex(hex)` -> `!Felt`
  - Input: hex scalar candidate.
  - Output: Stark field element.
  - Invariant: value < Stark field modulus.
  - Failure: `error.InvalidHex`, `error.Overflow`, `error.NotInField`.

- `core.ProjectivePoint.fromAffine(x, y)` -> `ProjectivePoint`
  - Input: affine coordinates.
  - Output: projective point with `z = 1`.
  - Invariant: representation-level validity only in Phase 0.
  - Failure: none in Phase 0; strict curve checks deferred.

- `kms.Bip44Path.parse(path)` -> `!Bip44Path`
  - Input: path string, expected `m/44'/coin'/account'/change/index`.
  - Output: structured path.
  - Invariants:
    - Exactly 6 segments.
    - Hardened flags on purpose, coin, account.
    - `change` and `index` non-hardened.
  - Failure: `error.InvalidPath`, `error.InvalidSegment`.

## Security and Correctness Invariants

- `Felt` values must remain canonical at construction boundaries.
- Domain/core modules do not perform implicit allocation unless requested.
- Any operation not yet implemented must fail explicitly with
  `error.Unimplemented` (never silent fallback).
- Future constant-time requirements:
  - Scalar arithmetic and hash internals will need dedicated timing analysis.

## Failure Modes and Handling

- Parse/format failures return typed errors.
- Unimplemented cryptography always returns `error.Unimplemented`.
- No panic-driven control flow in library APIs.

## Target Architecture

```
zig/
  build.zig
  build.zig.zon
  src/
    root.zig
    core/
      root.zig
      u256.zig
      felt.zig
      curve.zig
    crypto/
      root.zig
      pedersen.zig
      poseidon.zig
    kms/
      root.zig
      bip44.zig
    she/root.zig
    tongo/root.zig
    tests/smoke.zig
```

## Migration Plan

### Phase 0 (now)

- Workspace and module boundaries.
- Deterministic parsing/representation types.
- Test harness and CI entrypoint (`zig build test`).

### Phase 1

- Port `types-rs` subset needed by current Rust usage:
  - Felt construction/parsing/bytes.
  - Affine/projective point representation.
  - Deterministic conversion utilities.

### Phase 2

- Implement Pedersen/Poseidon primitives in Zig.
- Add cross-language parity vectors (Rust-generated vectors as fixtures).

### Phase 3

- Port KMS derivation internals (BIP-39/BIP-32/BIP-44 compatible behavior).
- Preserve deterministic test vectors from existing Rust tests.

### Phase 4

- Port SHE and TONGO operations against the Zig core.
- Add performance benchmarks and memory profiles.

## Verification Strategy

- Keep Rust as reference oracle during migration.
- Generate fixed input/output vectors from Rust and consume in Zig tests.
- Property tests:
  - Felt canonical roundtrip.
  - Path parse/format roundtrip.
  - Hash/vector conformance once implemented.

## Explicit Assumptions

- The initial commit is foundation-only; cryptographic primitives are not yet
  production-ready in Zig.
- We prioritize clean boundaries and deterministic contracts over breadth.
- We keep Rust code untouched while Zig implementation matures.
