# Design: hardware-backed STRK20 viewing keys

Date: 2026-08-12

## Problem

The original STRK20 helper derives a viewing key directly from a host-held
private key and is not scoped to a chain or pool. A hardware wallet cannot use
that interface without exporting its key. Replacing the existing function would
also break published Rust and WASM callers.

## Interface

The legacy `derive_strk20_viewing_key` and `deriveStrk20ViewingKey` interfaces
remain unchanged. The additive scoped path is:

1. `strk20_viewing_key_message_hash(chain_id, pool_address)` canonicalizes the
   scope and returns the hash to sign.
2. The hardware device signs that hash and supplies its public-key x-coordinate
   and `(r, s)` signature.
3. `fold_strk20_viewing_key(public_key, message_hash, r, s)` verifies the
   signature before folding it into the pool's viewing-key range.

`derive_scoped_strk20_viewing_key` composes those stages for host-held keys. The
WASM exports mirror the same interface.

## Invariants

- Scope components have one accepted spelling: shortest-form lowercase,
  non-zero, `0x`-prefixed felts.
- The fold rejects malformed signatures and signatures for another public key
  or message.
- Every successful scoped result satisfies `1 <= key < floor(n / 2)`, matching
  the privacy-pool contract's strict check. Zero and the two half-order fixed
  points map to `1`, matching the current privacy client.
- Existing unscoped known-answer vectors and export signatures do not change.

## Failure modes and limits

The caller must supply the expected account public key; verification proves the
signature matches that key, not that the caller selected the right account.
Scope and signature errors are returned at both Rust and WASM boundaries. WASM
felt inputs are round-tripped so values at or above the field prime cannot alias
to a different field element.

Ledger's Starknet app exposes blind hash signing and uses deterministic signing,
but device/app-version interoperability remains an integration test requirement.
This change does not claim hardware certification or stable signatures across
firmware versions; consumers should persist a registered viewing key.
