# Design: split SDK operations by protocol flow

Date: 2026-08-11

## Problem

`crates/sdk/src/operations.rs` mixed five independent Tongo proof flows, their
shared data types, cryptographic helpers, and tests in one 1,549-line file. The
public API was coherent, but changing one operation required reviewers to load
the implementation details of all five.

## Goals

- Give fund, transfer, rollover, withdraw, and ragequit separate implementation
  modules.
- Keep `krusty_kms_sdk::operations::*` and the crate-root re-exports unchanged.
- Keep the refactor mechanical: no proof transcript, validation, or
  serialization changes.
- Isolate the two genuinely shared curve helpers and the operation tests.

## Non-goals

- Changing any public function, parameter, or proof type.
- Refactoring the cryptographic algorithms inside an operation.
- Changing the FFI, WASM, or client adapter surfaces.

## Design

`operations.rs` remains the public facade and continues to own all public
parameter and proof structures. Each operation implementation moves into a
private `operations/<operation>.rs` module and is re-exported from the facade.
Curve helpers shared by transfer, withdraw, and ragequit live in a private
`shared.rs`; unit tests live in `tests.rs`.

This preserves downstream paths while making operation ownership explicit.
Future algorithmic refactors can now stay within one private module.

## Invariants

- Existing public Rust paths remain available.
- Proof transcript inputs and their ordering remain byte-for-byte equivalent.
- Feature behavior remains identical with and without the `parallel` feature.
- No new workspace dependency edge is introduced.

## Failure modes

- A missed import or visibility change fails normal compilation and tests.
- Public surface drift fails the design-note and semver guardrails.
- Moving or changing transcript logic would fail the checked-in proof vectors
  and cross-compatibility tests.
