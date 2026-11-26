# SNIP-12 domains hashed from their declared type

`compute_typed_data_message_hash` hashes the SNIP-12 domain from its declared
`StarknetDomain` or `StarkNetDomain` type, as starknet.js does (#276). The
domain's `revision` value selects the revision. The declared domain fields may
be any order or subset of `name`, `version`, `chainId` and `revision`, typed
`felt`, or `shortstring` in revision 1. The pinned `starknet-rust-core` decoder
accepts only the canonical domain type, so it decodes the message with that
type and placeholder domain values, and krusty hashes the domain itself.

The rule stays exact-or-fail-closed. A domain value the type does not declare
is rejected, except `revision`, so a displayed value cannot go unsigned. Types
named after a built-in or preset type are rejected, because starknet.js lets
such a type shadow a built-in type (and rejects presets) while the pinned
decoder resolves the built-in.

The domain handling lives in `crates/kms/src/typed_data_domain.rs`, which keeps
`typed_data.rs` and `typed_data_compat.rs` within their file-size ratchet. The
file-size baseline therefore only tightens: `typed_data.rs` drops from 391 to
386 lines, and `typed_data_compat.rs` (305 lines) falls under the soft limit
and leaves the baseline.
