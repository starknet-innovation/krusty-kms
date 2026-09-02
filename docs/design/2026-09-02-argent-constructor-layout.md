# Argent constructor calldata follows the class version

Date: 2026-09-02. Status: accepted. Origin: security audit finding H-1.

## Problem

`ArgentAccount::build_constructor_calldata` emitted `[0, owner, 0]` for every
Argent class hash. Argent v0.4.0's constructor is
`(owner: Signer, guardian: Option<Signer>)`; Cairo serialises `Option::None`
as the tag `1`, so `[0, owner, 0]` is a `Some` tag with no payload and cannot
be deserialised by any class. Argent v0.3.0 / v0.3.1 take
`(owner: felt252, guardian: felt252)` and were fed the same shape. Every
Argent address produced by `krusty-kms`, the gateway, discovery, and the WASM
`deriveArgentAccountAddress` export was undeployable. The repository's on-chain
vector already contradicted the encoding; its test asserted a mismatch and
attributed it to a "server-provided salt".

## Decision

- `ArgentConstructorLayout { OwnerGuardianFelts, SignerWithOptionalGuardian }`
  owns the calldata shape. The guardian `None` tag is produced by the shared
  `serialize_cairo_none()`, so the Argent path and the Tongo serialiser agree
  by construction.
- `ArgentAccount::with_class_hash` selects the layout from the known
  v0.3.0 / v0.3.1 / v0.4.0 class hashes; an unknown class hash keeps the
  latest (v0.4.0) layout. `with_class_hash_and_layout` and
  `constructor_layout()` make the choice explicit; `layout_for_class_hash`
  lets callers validate.
- The Argent preset moves to `crates/kms/src/account_class/argent.rs`. The
  file-size baseline for `account_class.rs` ratchets down (585 → 520 lines);
  no baseline grows.

| Class           | Cairo constructor                           | Calldata        |
|-----------------|---------------------------------------------|-----------------|
| v0.3.0 / v0.3.1 | `(owner: felt252, guardian: felt252)`       | `[owner, 0]`    |
| v0.4.0          | `(owner: Signer, guardian: Option<Signer>)` | `[0, owner, 1]` |

## Laws (tested)

1. `SignerWithOptionalGuardian.constructor_calldata(pk) == [0, pk] ++ serialize_cairo_none()`.
2. `OwnerGuardianFelts.constructor_calldata(pk) == [pk, 0]` for both v0.3.x hashes.
3. `ArgentAccount::new().calculate_address(pk, SaltPolicy::PublicKey)` equals
   the deployed v0.4.0 account in `crates/kms/tests/discovery_test/vectors.rs`
   (also reproduced independently with starknet-rs).
4. The previous `[0, pk, 0]` encoding does not reproduce that address.

## Alternatives considered

- One struct per Argent version: more public surface, and callers already
  select by class hash.
- Rejecting unknown class hashes in `with_class_hash`: would break existing
  callers; the latest-layout default plus an explicit override keeps the API
  additive and patch-compatible.

## Release note

Workspace 0.10.0 is unpublished; the fix lands in that release. Users of the
published crates (0.7.0 and below) must not fund Argent addresses derived by
those versions and must re-derive them.
