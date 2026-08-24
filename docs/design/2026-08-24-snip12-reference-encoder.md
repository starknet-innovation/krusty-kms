# Canonical SNIP-12 typed-data encoding

## Context

The KMS crate exposed typed-data hashing through Rust and WASM but maintained
an independent partial SNIP-12 encoder. Differential review found that accepted
revision-1 strings and preset `u256` values produced hashes different from the
locked Starknet reference implementation. Undeclared message members were also
ignored, so differently displayed JSON documents could share a signing hash.

## Decision

Keep the existing `compute_typed_data_message_hash` public API and delegate
parsing, revision selection, encoding, and hashing to the already locked
`starknet-rust-core 0.19.1` implementation. Reject typed-data JSON larger than
256 KiB before deserialization so Rust, FFI, and WASM callers share a bounded
input policy.

The local encoder and its self-referential tests are removed. Tests instead use
the reference revision-0, revision-1 string, and revision-1 preset-type hashes,
plus negative vectors for extra fields, missing fields, inconsistent revisions,
and oversized documents.

## Compatibility and failure modes

This is intentionally compatibility-affecting. Documents previously accepted
but encoded noncanonically now either produce the standard hash or fail closed.
Consumers must not retain old signatures for those documents as canonical
SNIP-12 signatures.

Malformed documents surface as the existing KMS JSON/serialization errors, so
the Rust and WASM function signatures remain unchanged. The reference encoder
selects Pedersen for revision 0 and Poseidon for revision 1 and enforces exact
field/type semantics at hash time.
