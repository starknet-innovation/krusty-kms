# SNIP-12 documents refused where starknet.js hashes differently

`compute_typed_data_message_hash` refuses SNIP-12 documents that the pinned
`starknet-rust-core` parser would read differently from starknet.js (#275):
declared types named after a built-in or preset, type and field names whose
escaping or sort order differ between the two, padded enum variant types, and
revision 1-only types or enum definitions in a revision 0 document. Refusal
keeps the exact-or-fail-closed rule from #108 without forking the upstream
type-hash logic.

The checks live in `crates/kms/src/typed_data_checks.rs`, declared from
`typed_data_compat.rs` with `#[path]`. Moving `reject_duplicate_json_keys`
there too shrinks `typed_data_compat.rs` from 385 to 379 lines, so its
file-size baseline only tightens.
