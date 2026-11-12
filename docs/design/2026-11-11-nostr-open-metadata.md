# Return replay metadata from Nostr application-data opening

Date: 2026-11-11. Status: proposed. Issue: #234.

## Problem

`open_nostr_application_data` checks the gift-wrap id and the rumor id, then
discards both, along with the rumor's `created_at`. Opening is stateless, so a
relay can deliver a stored wrap again, and the sender or recipient can re-wrap
the same seal under a new ephemeral key. Each delivery opens to the same
authenticated data. Callers own replay protection but get no data to do it
with.

## Decision

Add `open_nostr_application_data_with_metadata`, returning a
`#[non_exhaustive]` `OpenedNostrApplicationData` that holds the existing
`NostrApplicationData` plus:

- `wrap_id`: the verified gift-wrap event id. Deduplicating on it drops relay
  replays.
- `rumor_id`: the verified rumor event id. It does not change when the seal is
  re-wrapped, so deduplicating on it also drops re-wraps.
- `created_at`: the rumor's timestamp, NIP-59's canonical time. It is
  authenticated as the sender's claim, not as a trusted clock.

`open_nostr_application_data` delegates to the new function and drops the
metadata. Adding fields to `NostrApplicationData` itself would break callers,
because all its fields are public and it is not `#[non_exhaustive]`. Krusty
does not keep replay state; callers hold the processed-id set and their own
freshness policy.

WASM `openNostrApplicationData` adds `wrapId`, `rumorId` and `createdAt` to
its JSON result. The export signature is unchanged.

The rustdoc also states two existing limits:

- Content must fit the nested NIP-44 envelope after JSON escaping, which
  allows 40,614 to 40,742 escaped bytes depending on the identifier length.
- `wrap_nostr_application_data` reads the system clock, which is unavailable
  on `wasm32-unknown-unknown`.

The generic Nostr event code (event structs, id hashing, signing,
verification and hex decoding) moves unchanged into the private submodule
`nostr_application_data/event.rs`. Without the move,
`nostr_application_data.rs` would pass the 350-line file-size soft limit.

## Compatibility and verification

Additive only, so a minor bump. A core test opens one wrap twice and gets
identical results. It then re-wraps the same seal under a new ephemeral key and
checks that the wrap id changes and the rumor id does not, and that
`created_at` equals the wrap time. The WASM round-trip test checks the three
new JSON fields.
