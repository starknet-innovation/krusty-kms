# Remove the remaining deprecated APIs before 1.0.0

Date: 2026-11-05. Status: accepted.

After 1.0.0, removing a public item needs a major version. Two deprecated
items were still public after `felt_to_u256_pair` was removed (#205):

- `ArgentAccount::with_class_hash` (`krusty-kms`), deprecated in
  `2026-09-02-argent-constructor-layout.md`. For an unrecognised class hash
  it assumes the v0.4.0 constructor layout. Argent has changed its
  constructor before, so the guess can yield an address that never deploys.
  Keeping a constructor that fails this way in a stable API is a standing
  footgun. Replacements: `try_with_class_hash` (rejects unknown hashes) and
  `with_class_hash_and_layout` (caller states the layout).
- `decrypt_cipher_balance_with_default_limit` (`krusty-kms-client`),
  deprecated since 0.3.0 in favour of `decrypt_cipher_balance_with_limit`,
  which makes the discrete-log search bound explicit.
  `DEFAULT_DECRYPT_SEARCH_LIMIT` stays public, so the old behaviour is one
  argument away.

No workspace crate, WASM export or C ABI function called either one, so the
only code removed is the two functions, the client re-export and the test
that pinned the deprecated guessing behaviour. `BraavosAccount::with_class_hash`
is not deprecated and is unchanged.

Not in scope: `CachePolicy::max_entries` in `krusty-kms-domain` is documented
as deprecated (ignored for gateway eviction) but it is an oracle wire field,
not just a Rust API. Removing it is a protocol decision, kept separate.

`cargo-semver-checks` reports these removals as `function_missing` /
`inherent_method_missing`. That is intended, and the 1.0.0 release PR
carries the major bump.
