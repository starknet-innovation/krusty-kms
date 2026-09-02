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
- The layout is selected from the known v0.3.0 / v0.3.1 / v0.4.0 class
  hashes. An unrecognised class hash is **rejected** unless the caller states
  the layout: `try_with_class_hash` (fallible) or `with_class_hash_and_layout`
  (explicit). `layout_for_class_hash` is the canonical map and lets callers
  validate. `with_class_hash` kept the latest-layout guess and is deprecated —
  the amendment at the end of this note records why that was reversed.
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
- Rejecting unknown class hashes in `with_class_hash` itself: would break
  existing callers. Superseded (see the amendment below): the rejection lives
  in a new fallible constructor instead, so the API stays additive.

## Release note

Workspace 0.10.0 is unpublished; the fix lands in that release. Users of the
published crates (0.7.0 and below) must not fund Argent addresses derived by
those versions and must re-derive them.

## Amendment — unknown class hashes are rejected

The original decision kept the latest (v0.4.0) layout for an unrecognised
class hash. That is unsafe for the same reason this note exists: Argent has
changed its constructor once already, so an unrecognised class may accept the
v0.4.0 calldata or may reject it, and the class hash alone does not say which.
Where it rejects, the derived address is undeployable and funds sent there are
stranded. The objection is to deriving on an unverified guess, not to the
guess always being wrong.

`ArgentAccount::try_with_class_hash` now returns
`KmsError::InvalidClassHash` for a class hash outside `layout_for_class_hash`.
The two surfaces that accept a caller-supplied class hash use it: the WASM
`deriveArgentAccountAddress` export and gateway/oracle Argent resolution. The
gateway rejects even under `allow_unlisted_class_hash=true`, because waiving
the allowlist cannot supply a constructor layout.

`with_class_hash` keeps the guessing behaviour and is deprecated rather than
removed, so the API stays additive; `with_class_hash_and_layout` is the
supported way to derive for a class this crate does not know. Discovery pairs
each static class hash with its layout and uses that constructor, so
candidate generation stays infallible.

Known ceiling: the gateway/oracle and WASM surfaces cannot state a layout —
`AccountClassSpec` carries no layout field — so a genuinely new Argent class
needs a krusty release to become derivable there. Adding a layout to the spec
is the upgrade path if that becomes urgent.
