# SNIP-12 typed-data parity with starknet.js

## Behavior

`compute_typed_data_message_hash` and the WASM export accept the same five
reported document shapes as starknet.js 10.8.0: positive numeric and decimal
string `i128`, a revision-0 `StarkNetDomain` with a `revision: felt` field and
value `"0"`, `StarknetDomain` as the primary type, hexadecimal `selector`
values, and uppercase `0X` felt strings. starknet.js encodes `felt` and
`shortstring` with the same `getHex` rule, so an uppercase `0X` hex string is
also a numeric value for a `shortstring` field, not its ASCII text. A selector beginning with `0x` or
`0X` and containing hex digits is a felt value; other selectors are hashed as
names. Hex values must fit in a Stark felt. The export signature is unchanged.

## Invariants and implementation

The 256 KiB input limit, duplicate-key rejection, strict envelope, strict
domain, and exact struct fields remain in force. The pinned Rust typed-data
decoder validates type definitions and most primitive encodings. A private
compatibility module applies the five narrowly scoped rules while recursively
hashing structs, arrays, enums, and Merkle trees with the revision's hash
function. For the one supported four-field revision-0 domain, it removes the
extra type field only for decoder validation, then hashes the original
four-field signature and values. Decoding and encoding errors continue to use
the generic typed-data error, so attacker-supplied names and values are not
reflected.

The selector-as-hex and uppercase-felt cases intentionally change previously
returned hashes. The hash now matches the JSON's interpretation in
starknet.js and standard dapp verification. Rust fixtures hold expected
hashes generated independently with starknet.js 10.8.0; the TypeScript
cross-test recomputes them in CI. The original three fixtures remain checked
against starknet.js 10.0.2. No new dependency or public Rust API is needed.

## Guardrail baseline

`typed_data_compat.rs` enters the file-size baseline at 385 lines, above the
350-line soft limit and below the 500-line hard limit. Its helpers implement one
private invariant: the compatibility overrides must compose through every
nested hash. Splitting them would spread that invariant across files.
`typed_data.rs` shrinks from 394 to 391 lines.
