# Bound keystore and NATS inputs, fail the oracle confirm gate closed, tokenise the unsafe scan

Date: 2026-11-04. Status: accepted. Origin: the 2026-11-04 security audit of
`ce8d00ef` (Medium findings M-1, M-3, M-4, M-5; M-2 is discussed last).

## Problem

Four production Medium findings share one shape: an input the code treats as
trusted (a keystore file, a NATS frame, an environment variable, a Rust source
file) is attacker- or operator-controlled, and nothing bounds it before the
expensive or security-relevant step runs.

## Contract

No public API, FFI, WASM or dependency changes. Every existing signature is
unchanged; every accepted input stays accepted except the ones listed.

### M-1: native keystore scrypt cost and salt length (`krusty-kms`)

- Inputs: v1 (`decrypt_keystore`) and v3 (`decrypt_ethers_keystore`) keystore
  JSON, reached from the WASM `decryptKeystore` / `decryptEthersKeystore`
  exports.
- Before: the v1 path only checked that `n` is a power of two up to 2^20.
  With the format's fixed `r = 8` that is a 1 GiB scrypt allocation before
  the password is checked (the audit measured 1.08 GB RSS and 1.5 s per
  attempt; on the old code the new test takes 55 s). Neither path bounded
  the salt, which scrypt's PBKDF2 stage re-hashes `4·r·p` times.
- After: `decrypt_keystore` runs the same `validate_scrypt_resource_params`
  as the v3 path with the format's fixed `r = 8, p = 1, dklen = 32`, so the
  256 MiB memory ceiling applies to both formats. Both paths decode the salt
  through one `decode_salt` helper that rejects more than 128 bytes (both
  formats write 16 or 32). Rejections are `DeserializationError`, a property
  of the file, not `CryptoError`, which would tell a caller to retry the
  password.
- Invariants pinned by `keystore/tests/limits.rs`: `n = 2^20` is rejected
  with the memory-ceiling message (so before `derive_scrypt_key`); a
  129-byte salt is rejected on both formats; a 128-byte salt still reaches
  the KDF and fails on the password-dependent step, so the bound is exact.
- File layout: `keystore.rs` sits on the file-size baseline and cannot grow,
  so the malformed-metadata and resource-limit tests moved from its inline
  test module to `crates/kms/src/keystore/tests/limits.rs` (a child of that
  module), and the new tests live there. No baseline changed.

### M-3: NATS coordinator payload cap (`krusty-kms-client`, `nats` feature)

- Input: the payload of every `MSG` the subscribed NATS server delivers.
- Before: the HTTP coordinator capped responses at 1 MiB but the NATS
  subscriber parsed whatever arrived. `async-nats` 0.51 enforces
  `max_payload` on publish only and buffers the server-declared length on
  receive; the audit's fake server pushed one 256 MiB frame into 266 MiB of
  resident memory.
- After: the 1 MiB cap is one crate-private constant
  (`multisig::MAX_COORDINATOR_PAYLOAD_BYTES`) shared by both transports. The
  subscribe closure now calls `decode_subscribed_payload`, which rejects
  `payload.len()` above the cap before `serde_json` sees a byte, then parses
  and runs the existing receive-side validation.
- Not fixed here: the transport-level buffer. The module docs say so; the
  allocation of one oversized frame needs a receive-side cap upstream in
  `async-nats`.
- Invariants pinned by the tests in `nats.rs` (no server needed): a payload
  one byte over the cap that starts with `{` fails with the byte-limit
  error, not a JSON error, so nothing was parsed; a payload exactly at the
  cap reaches the parser, so the HTTP coordinator's limit still fits.

### M-4: `KRUSTY_ORACLE_REQUIRE_CONFIRM` fails closed (`krusty-kms-oracle`)

- Input: the environment variable, read per request.
- Before: only the literals `1`, `true`, `TRUE`, `yes`, `YES` enabled the
  gate. `True`, `Yes`, `on`, `enabled`, `y` or a padded value silently
  disabled it, with no error or log, while the operator believed it was on.
- After: `confirm_gate_enabled` trims and lowercases the value. Only an
  explicit opt-out (`0`, `false`, `no`, `off`, `n`, `disabled`) or an empty
  value leaves the gate off; every other value, including spellings the
  function does not know and a non-UTF-8 value, turns it on. "Treat
  unrecognised as enabled" was chosen over "fail startup" because the crate
  has no startup phase (the oracle reads the variable on each request) and
  no error channel before the first response; failing closed per request
  keeps the existing error model. `docs/oracle-stdio-v1.md` documents the
  accepted spellings.
- Behaviour change for operators: a value that used to disable the gate by
  accident (`True`, `on`, `y`, …) now enables it, which is what they meant.
  A deliberate `off` keeps working.
- Invariants pinned by `tests/confirm_gate.rs`: a table over every spelling
  above; end-to-end, ` True `, `Yes`, `on`, `enabled` and `y` reject a
  privileged request without `confirm`, and `0`, `false`, `off`, `no` and
  the empty string let it through.

### M-5: tokenised `unsafe` scan (`.github/scripts`, not a published crate)

- Input: every production `.rs` file, scanned by
  `check-unsafe-allowlist.sh`.
- Before: comments, then strings, were stripped with regexes and char
  literals were never handled. A `'"'` char literal read as a string opener
  and a `"/*"` string literal read as a comment opener, and an `unsafe` block
  after either was invisible. The script also accepted
  `#![allow(unsafe_code)]` on any crate root, so once the scan was evaded
  nothing in CI objected.
- After: the lexer that `check-code-complexity.py` already used to track
  strings, raw strings, char literals and nested block comments across lines
  moved to `.github/scripts/lib/rust_scanner.py` (a parity check against
  the old copy over every workspace file found no difference). Its new
  `strip_line` blanks non-code text column-for-column; both scripts use it.
  The scan looks for `\bunsafe\b` in the blanked text only. Crate roots must
  declare `forbid` or `deny(unsafe_code)`; `allow(unsafe_code)` is accepted
  on `crates/ffi/src/lib.rs` alone, and the attribute is matched in code,
  not in doc comments. The script takes an optional root argument so it can
  run against fixtures.
- Invariants pinned by `test-check-unsafe-allowlist.sh` (run by the
  guardrails workflow next to the checker): a plain `unsafe` fails; the
  char-literal and string-literal evasions fail; `unsafe` after a multi-line
  string closes fails; a crate-level allow outside `crates/ffi` fails; a
  root without a policy fails; look-alike text in doc comments, nested block
  comments, strings, raw strings, char literals and a multi-line string
  passes; the allowlisted `secret_felt.rs` and FFI crate pass; experimental
  trees are ignored; the real repository passes.

## Deferred: M-2, RPC response bodies

The audit asks for a byte cap on JSON-RPC response bodies. It is deferred to
the next minor release because it needs a breaking transport type change:
`create_provider` returns `JsonRpcClient<HttpTransport>`, and that exact
type is a public field or parameter of `Wallet`, `TongoContract`,
`Erc20Client`, `StakingClient`, `EventScanner`, `Multisig`, the wallet-api
adapter and `StarknetGatewayBackend`, so a `JsonRpcTransport` wrapper
changes a type parameter that `cargo-semver-checks` rejects at 0.14.
`reqwest` 0.13 offers no body-size setting, and its `connector_layer` hook
cannot wrap the connection because `Conn` is private, so the cap cannot be
hidden inside the `reqwest::Client` that `HttpTransport` holds. Until then
the 10 s connect, 15 s read and 30 s total timeouts in `provider.rs` bound
the download by time only, not by bytes. A generic transport parameter
across those types was considered and rejected for a fix PR; the wrapper
lands with the minor bump that may change the public type.

## Verification

`bash tools/check.sh rust` and `bash tools/check.sh guardrails` pass, and
each new test was run once against the reverted fix and fails there.
