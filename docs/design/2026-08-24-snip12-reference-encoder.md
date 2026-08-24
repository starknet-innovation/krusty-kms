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
`starknet-rust-core =0.19.1` implementation. The Starknet Rust dependency
family is declared centrally in `[workspace.dependencies]` with exact versions
so published library consumers cannot silently select a later encoder patch.
Reject typed-data JSON larger than 256 KiB before deserialization so parsing
work and the amplified in-memory representation have a shared bound. The input
string itself has already been allocated before this API receives `&str`.

The local encoder and its self-referential tests are removed. Rust tests consume
revision-0, revision-1 string, and revision-1 preset-type fixtures that the
cross-compatibility suite independently hashes with starknet.js 10.0.2. Negative
vectors cover extra fields, missing fields, inconsistent revisions, redacted
encoder errors, and the exact and over-limit size boundaries.

Protocol reference: [SNIP-12](https://github.com/starknet-io/SNIPs/blob/main/SNIPS/snip-12.md).

The SNIP-12 message prefix is the felt encoding of the short string
`StarkNet Message`, not the result of hashing that string. The reference encoder
owns this distinction; reintroducing a local prefix calculation would reopen a
subtle cross-SDK divergence risk.

## Compatibility and failure modes

This is intentionally compatibility-affecting. Documents previously accepted
but encoded noncanonically now either produce the standard hash or fail closed.
Consumers must not retain old signatures for those documents as canonical
SNIP-12 signatures.

Malformed documents surface as the existing KMS JSON/serialization errors, so
the Rust and WASM function signatures remain unchanged. Reference-encoder
details are replaced with a fixed error string because field and type names are
attacker-controlled and may be logged. The encoder selects Pedersen for
revision 0 and Poseidon for revision 1 and enforces exact field/type semantics
at hash time.
