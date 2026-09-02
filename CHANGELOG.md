# Changelog

All notable changes to the published Rust crates are documented here.

## [Unreleased]

### Added

- Add `krusty_kms_common::fee::ResourceBoundsCeiling`, a validated per-dimension
  ceiling on V3 resource bounds, together with `Wallet::with_fee_ceiling`,
  `deploy_oz_account_with_fee_ceiling`, and
  `StarknetGatewayBackend::with_deploy_fee_ceiling` to apply it. Existing APIs
  are unchanged and stay RPC-estimated when no ceiling is supplied.

### Security

- Gateway deploy and derive flows no longer hold a starknet-rs `SigningKey`
  (a plain, non-zeroizing `Felt` copy of the private key) across the deploy
  acceptance wait. Public-key derivation and descriptor validation use the
  kms-native `stark_public_key` path; the signer and account factory are
  confined to the transaction submission and dropped before any polling
  begins. Zero or out-of-range private keys now return an error instead of
  panicking inside the curve arithmetic.
- Provider transport failures no longer echo the RPC endpoint URL. starknet-rs
  forwards `reqwest::Error`'s `Display`, which includes the full request URL
  (path and query commonly carry the provider API key), into
  `ProviderError::Other`; the gateway stored that text in the operation log
  and returned it to oracle callers, and the client surfaced it in
  `KmsError::RpcError`. Transport errors now map to a fixed
  `provider transport error: <kind>` (`timeout`, `connect`, `status <code>`,
  `decode`, `json-rpc code <n>`, `other`); typed Starknet JSON-RPC errors keep
  their message. Cleartext-URL rejection messages in `create_provider` show
  only `scheme://host[:port]`. Adds `krusty_kms_common::error::redact_url` and
  `REDACTED_URL_PLACEHOLDER` for the same purpose in downstream code.
- `cargo-deny` now rejects duplicate dependency versions. Every remaining
  duplicate is an individually justified `skip` in `deny.toml` naming the
  third-party path that forces it (see `docs/supply-chain.md`), so a new
  second copy of a crypto or parsing crate fails CI instead of warning.

### Changed

- Sign and verify Stark ECDSA with `starknet-rust-crypto` 0.19.1, the version the
  `starknet-rust` 0.19.1 stack already links, instead of a second 0.9.0 copy. The
  public API and the signing test vectors are unchanged; the duplicate
  `starknet-rust-crypto`, `starknet-rust-curve`, and `crypto-bigint` 0.5 builds
  leave the lockfile.

## [0.10.0] - 2026-09-02

### Added

- Add mnemonic-bound NIP-44 and NIP-59 application envelopes to the Rust and
  WASM APIs, including strict event, recipient, identifier, entropy, and
  nested-payload validation.

### Security

- Fix Argent account constructor calldata. The v0.4.0 layout now encodes the
  absent guardian as the Cairo `Option::None` tag (`[0, owner, 1]`), and the
  v0.3.0 / v0.3.1 class hashes use their `(owner, guardian)` felt layout
  (`[owner, 0]`). Previously every Argent address computed by `krusty-kms`
  (`ArgentAccount`), the gateway, account discovery, and the WASM
  `deriveArgentAccountAddress` export used `[0, owner, 0]`, which no Argent
  class can deserialise, so nothing could ever be deployed at those addresses.
  **Do not fund Argent addresses derived with any earlier krusty-kms release
  (0.7.0 and below on crates.io)**; re-derive them with this release before
  use. Funds already sent to such an address cannot be recovered through
  account deployment. The fix is verified
  against a deployed Argent v0.4.0 account
  (`crates/kms/tests/discovery_test`). `ArgentAccount::with_class_hash` now
  selects the layout from known class hashes; `ArgentConstructorLayout` and
  `ArgentAccount::with_class_hash_and_layout` make it explicit.
- Bound Starknet RPC and multisig coordinator connect/read/request deadlines,
  cap coordinator bodies before JSON parsing, and bound event pagination by
  wall time, pages, events, serialized bytes, and continuation-token size. RPC
  redirects and ambient proxies are disabled so request bodies remain on the
  configured origin.
- Use the canonical SNIP-12 encoder for typed-data hashing. Previously accepted
  noncanonical documents can now produce a different hash or fail closed, and
  signatures created over those old hashes must not be treated as canonical
  SNIP-12 signatures.

### Changed

- Use the non-yanked `chacha20` 0.10.2 release for NIP-44 encryption.
- C-ABI `KmsFelt` / `KmsProjectivePoint` decode sites bail with `let ... else`
  rather than a match arm, and the decoders report failure as a typed
  `InvalidInput` widened to `KMS_ERR_INVALID_INPUT` once at the boundary. No
  ABI, status-code, or behaviour change; it clears a critical
  `rust/hard-coded-cryptographic-value` alert in which an error-code constant
  returned from a match arm appeared to reach a `salt` argument.

## [0.7.0] - 2026-08-16

### Security

- Reject cleartext `http://localhost` RPC URLs unless every resolved address
  is loopback, and pin the HTTP client to that full RRset so later DNS
  lookups cannot rebind to metadata or RFC1918. `krusty-kms-client` now
  uses reqwest 0.13 so the pin uses the same client type as `HttpTransport`.

### Added

- Add chain- and pool-scoped STRK20 viewing-key derivation stages for hardware
  signers. Signature folding verifies the expected public key and message, and
  preserves the original unscoped Rust and WASM APIs for compatibility.

### Fixed

- Reject non-canonical field encodings in every C-ABI `KmsFelt` struct decoder
  instead of silently reducing them, including projective identity coordinates.

## [0.6.0] - 2026-08-11

This release consolidates every change merged after `0.5.4`. The previously prepared
`0.6.0` through `0.9.7` version candidates were never tagged or published.

### SDK proof operations

- Split the Tongo SDK proof operations and their tests into focused per-operation
  modules while preserving the existing public API.

### Dependency compatibility

- Adapt scrypt KDF call sites to `scrypt` 0.12 `Params::new` (log_n, r, p).

- Bump `starknet-rust` to 0.19.1 across wallet-api/client/gateway (and controller)
  and adapt call sites for Result-returning curve helpers.
- Raise workspace `starknet-types-core` minimum to 0.2.4.

- Coordinate `aes` 0.9 + `ctr` 0.10 (shared `cipher` 0.5) for Web3 secret
  storage keystore decryption.

- Migrate to `rand`/`rand_core` 0.10 (`TryRng`/`SysRng` renames) and
  `getrandom` 0.4 for SysRng/wasm_js compatibility. Krusty public helpers
  (`random_felt`, `fill_random_bytes`, WASM `randomFelt`/`randomBytesHex`)
  keep the same signatures; fallible helpers still surface `getrandom::Error`
  (now from getrandom 0.4).

- Migrate scalar modular arithmetic to `crypto-bigint` 0.7 `ConstMontyForm`
  (replacing the removed `Residue` API).

### Maintainability and public API hygiene

#### Added

- Maintainability guardrails: CI fitness checks for file-size ratchet, dependency
  DAG, `unsafe` policy, secret hygiene, FFI/WASM surface freezes, design-note
  gates, `cargo-deny`, rustdoc link checks, and locked `cargo-semver-checks`
  (see `docs/maintainability-guardrails.md`).

#### Fixed

- Align `TongoKeyPair` `Debug` with `NostrKeyPair` by redacting as `"***"`.
- Broken rustdoc intra-doc links in `SecretFelt`, range helpers, and OZ deploy
  docs.
- Set `license` metadata on `krusty-kms-cabi`.

#### Changed

- Keep `starknet-types-core` on a caret requirement (`"0.2.0"`) and rely on
  `Cargo.lock` + locked rustdoc JSON for semver checks (exact pins would break
  downstream resolution).

### Security hardening

Third security-hardening pass, covering the Medium and Low/Info findings
backlog from the full-repository audit (#46). Critical/High passes landed in
#41 and #45.

#### Changed

- **Breaking:** `SecretFelt::expose_secret_hex` now returns
  `Zeroizing<String>` instead of `String`, so exported key hex is scrubbed on
  drop (M-07). Callers that need an owned `String` must copy explicitly via
  `.as_str().to_owned()`.
- **Breaking:** `KmsError::InsufficientBalance` is now a fieldless variant.
  It previously carried `{ available, required }`, which leaked the exact
  confidential plaintext balance into JS/FFI error strings and logs (M-03).
  The same change applies to the wasm and gateway error mappings.
- **Breaking:** account-discovery secret accessors are now fallible.
  `CandidateAccount::{expose_private_key, with_secrets}` and
  `DerivedKeypair::{expose_private_key, with_secrets}` return `Result`, so a
  value deserialized from the public-only JSON form reports a missing key
  instead of yielding an empty string that could flow into signing or export
  paths (M-05). Both types now zeroize their private key on drop and expose
  `verify_key_binding()` to re-verify that the private key derives the stated
  public key after a serialization round-trip.
- **Breaking:** OpenZeppelin account discovery emits two candidates per
  derivation index — `salt = public_key` (matching the deploy/gateway
  default) plus the legacy `salt = 0` — so recovery no longer misses accounts
  deployed by this project's own flow (M-06). Callers that assumed a fixed
  candidate count per index must adjust.
- **Breaking:** the wasm `generateAccountAddresses` compact view now maps each
  wallet type to an **array** of every candidate address for that type, rather
  than a single address string:
  `{ "0": { "OpenZeppelin": ["0x…", "0x…"], … } }`. It previously kept only
  the first address per wallet type, which silently hid deployed accounts in a
  recovery path — three Argent legacy class hashes and four Argent Cairo 0
  proxy implementations were being discarded, and adding the OpenZeppelin
  `salt = public_key` variant above would have displaced the legacy
  `salt = 0` address this API used to return.
- **Breaking:** `WaitForAcceptance` policies are bounded more tightly:
  `timeout_ms` is capped at 15 minutes (was 24 hours) and `poll_interval_ms`
  must be at least 250 ms. Transports serve requests sequentially, so an
  unbounded wait monopolized the pipe and a tiny interval flooded the RPC
  endpoint (M-10). Use `SubmitOnly` plus `GetOperationStatus` polling to
  track slower deployments.
- **Breaking:** `krusty-kms-crypto`'s `test-utils` feature is renamed to
  `insecure-deterministic-rng`, and enabling it is no longer sufficient to
  activate the deterministic stream: `set_deterministic_rng` now also
  requires `KRUSTY_KMS_ALLOW_DETERMINISTIC_RNG=1` in the process
  environment, so a dependent crate turning the feature on through cargo
  feature unification cannot silently disable real entropy (M-20).
- Scalar arithmetic modulo the curve order is now constant-time, backed by
  `crypto-bigint` Montgomery residues instead of variable-time `num-bigint`.
  Proof responses derived from secret scalars (`s = r + c*x`) no longer leak
  key material through timing on shared hosts (M-02). Transcripts are
  unchanged — all checked-in prover and cross-language parity vectors still
  pass.
- Snapshot cache metadata leaving the gateway is quantized to a 5-second
  grid. The cache is shared across all callers, so exact timestamps on a
  `Hit` revealed when another caller last queried the same address (M-12).
  Internal freshness and TTL decisions still use exact values, and the cache
  entry retains the exact generation time so TTL deadlines are unaffected.

  `age_ms` is **not** the quantized true age. Quantizing the true age leaves
  the oracle intact, because the bucket *transition* is itself the signal: a
  caller polling a shared entry sees age flip at the instant `now` crosses
  `generated_at + 5s`, and knowing its own clock it can pin `generated_at` to
  its polling resolution. Both exposed fields are instead derived from
  independently quantized buckets —
  `generated = floor(generated_at / 5s)` and `age = ceil(now / 5s) - generated`
  — so every term is already known to the caller (its own clock, plus the
  `generated` bucket in the same response), `age_ms` conveys no additional
  information, and its transitions occur on absolute wall-clock boundaries
  simultaneously for every entry. Rounding `now` up keeps the reported age
  conservative: it may over-state age by up to one quantum but never
  under-states it, so a consumer cannot conclude an entry is fresher than it
  is.
- Snapshot requests are limited to 16 tracked tokens, since each token costs
  backend RPC calls (M-11).
- Only `https://` RPC endpoints are accepted by `create_provider`, with a
  loopback-only exception (`localhost`, `127.0.0.1`, `::1`) for local
  devnets (M-14).

#### Fixed

- Gateway `sign` verifies the request's `chain_id` against the configured
  backend before recording it in the signed provenance, so the attested
  chain is a verified fact rather than a caller claim (M-09).
- JNI string arguments are converted through an explicit UTF-16 → standard
  UTF-8 path instead of `GetStringUTFChars`' modified UTF-8 (CESU-8).
  Passphrases containing non-BMP characters now derive the same keys on the
  JVM as on Swift, Dart, and Rust; previously they diverged, making funds
  unreachable from one platform (M-22). Unpaired surrogates are rejected,
  and every extracted string buffer is securely wiped.
- `kms_felt_from_hex` and `kms_felt_from_bytes_be` reject non-canonical
  inputs (>= the field prime) instead of silently reducing them, which could
  turn a 32-byte key into a *different* key while the JSON paths rejected
  the same input (M-25).
- The FFI account registry recovers from mutex poisoning instead of failing
  every subsequent call for the process lifetime after one panic (M-23).
- Malformed SNIP-12 enum type strings (for example `"a)b("`) from
  dapp-supplied typed data return an error instead of panicking on an
  out-of-bounds slice (M-08).
- RPC felts are converted to `u128`/`u32` with explicit range checks.
  `get_rate` feeds `approve(amount * rate)`, where a silently truncated
  value would inflate the granted allowance (M-13).
- Plaintext key buffers are zeroized in `encrypt_private_key` and both
  intermediate copies inside `EthSigner::from_hex` (M-07).
- `decryptBalance`'s `max_search` is capped at 2^20 and `randomBytesHex`'s
  length at 1024 bytes, so JS callers cannot pin the calling thread or force
  an unbounded allocation (M-16). The cap is deliberately close to the
  existing default: the search is a linear scan costing a curve addition plus
  an affine conversion per step (~420k steps/sec natively in release, slower
  under wasm), so a nominally-finite ceiling like 2^32 would still occupy the
  calling thread for hours and provide no protection. Recovering larger
  balances needs a better algorithm, not a larger linear bound.
- `FeltHex::parse` rejects values that alias to a different field element,
  including exactly the field prime, which upstream `Felt::from_hex` accepts
  and maps to 0.
- BIP-44 derivation rejects `index`, `account_index`, and `coin_type` values
  with the BIP-32 hardened bit set. Path builders OR that bit in, so such a
  value silently aliased to another caller's key.
- `isValidStarkPrivateKey` now requires `0 < key < n`. Keys in `[n, p)`
  previously validated but silently reduce mod the curve order when signing,
  i.e. they alias to a different key.
- `Amount::to_human` no longer panics for `decimals >= 39`, where
  `10^decimals` overflows `u128`.

#### Security / supply chain

- The workspace-root `cargo-audit` ignore list is now empty; the ignores
  motivated by the workspace-excluded `krusty-kms-controller` crate moved to
  `crates/controller/.cargo/audit.toml`. Carrying them at the root masked
  the same advisories if a production dependency ever regressed onto an
  affected version (M-17).
- `account_sdk` is pinned by immutable commit rev rather than a mutable git
  tag (M-18).
- Verified and documented the publisher provenance of the `starknet-rust`
  crate family in `docs/supply-chain.md` (M-19).
- Both publish workflows now run fmt, clippy, the full test suite, and
  `cargo audit` as a gating job before publishing, and `npm publish` passes
  `--provenance` (M-21).
- Removed an orphaned, uncompiled, unaudited `wallet/eth.rs` (661 lines),
  configured Dependabot across all package ecosystems, and added
  keystore/key-material patterns to `.gitignore`.

### Internal refactoring

#### Changed

- Internal refactor only: split the gateway `backend.rs` module into focused
  submodules (backend interface, Starknet JSON-RPC implementation, acceptance
  polling, deploy error mapping, RPC helpers). Follow-up to #51/#55; no public
  API or behavior changes.

### Multisig coordination

#### Changed

- **Breaking:** multisig coordination notices are now cryptographically
  authenticated (#52). `MultisigCoordinator::publish`/`messages`/`subscribe`
  exchange a versioned `MultisigCoordinationEnvelope` (signed schema v1, or
  the legacy unsigned message as v0). New
  `SignedMultisigCoordinationMessage` carries the claimed actor's account
  signature over a domain-separated hash of
  `(topic, message_kind, payload_hash)`; receivers authenticate it against
  the on-chain signer set and the actor's account contract (SNIP-6
  `is_valid_signature`) via `Multisig::verify_signed_message`, or offline via
  `verify_with_stark_public_key`. Forged confirmation/revocation/execution
  notices and proposer/memo attribution tampering by a compromised
  coordinator no longer verify. Every verification entry point recomputes a
  proposal's `transaction_id` before considering the signature, since the
  signing hash covers `calls`/`salt` only transitively through that id.
  `verify_signed_message` pins its signer-set
  and signature reads to a single block hash, and envelope deserialization
  rejects any payload that carries `version` but is not a well-formed signed
  envelope, so authentication cannot be silently stripped. Verified notices
  prove actor authorization only — not publisher identity, freshness, or
  uniqueness — so consumers that tally them must deduplicate by
  `(actor, topic, message kind)`.

### Dependency surface

#### Changed

- **Breaking:** NATS multisig coordination is now opt-in through the
  `krusty-kms-client/nats` feature, removing its dependency subtree from the
  default client graph.
- Deduplicated Starknet signing onto Software Mansion's
  `starknet-rust-crypto` package and removed unused direct, test-only, and WASM
  dependencies across the workspace.
- Removed the archived `console_error_panic_hook` from the WASM packages.

### Internal refactoring (continued)

#### Changed

- Internal refactor only: split oversized source files into focused modules
  (`gateway` runtime, `client` multisig, `domain`, `oracle`, `wasm`
  account/signing, `kms` discovery, `crypto` ElGamal tests) per the PR #45
  review follow-up (#51). No public API or behavior changes; all crate-root
  paths are preserved via re-exports.

### Core security and account APIs

#### Changed

- **Breaking:** `stark_public_key` now returns `Result` and rejects zero or
  out-of-range Stark private keys via `validate_stark_private_key` (H-08),
  propagated through the WASM exports.
- **Breaking:** `Multisig::new` takes the expected `ChainId`, and
  `MultisigProposal` carries a `chain_id`; `confirm_proposal` rejects
  proposals and wallets bound to any other chain before signing (H-02
  follow-up).
- ElGamal: new `encrypt_strong`/`verify_strong` whose Fiat-Shamir challenge
  `H(prefix, pk, L, R, AL, AR)` additionally binds the public key and the `AR`
  commitment (H-01); legacy `encrypt`/`verify` retained for deployed
  verifiers. New `kms_elgamal_encrypt_strong` C ABI export, published in the
  C, JVM, Swift, and Dart bindings.
- Gateway operation IDs are random 128-bit hex instead of sequential (H-06),
  and OS-entropy failures now return a retryable `Internal` error instead of
  panicking.

#### Fixed

- Gateway wait loops: deadline arithmetic no longer overflows, per-poll sleeps
  are capped at the remaining deadline, and `timeout_ms`/`poll_interval_ms`
  are bounded by `MAX_WAIT_TIMEOUT_MS` (H-04).
- Snapshot cache policies clamp caller-provided `ttl_ms` and
  `stale_while_revalidate_ms` to server-side maximums (H-05).
- Multisig coordination: receive-side validation of coordinator messages
  (topic consistency, proposal transaction-id integrity) in the NATS and HTTP
  coordinators (H-02).
- FFI/JNI/Swift secret hygiene: `Zeroizing`/`SecretFelt` wrap mnemonics,
  seeds, derived keys, and ElGamal scalars across the FFI surface (H-11);
  binding-side copies are wiped with `memset_s`/`explicit_bzero` (H-12);
  Swift `ethSign` rejects non-32-byte keys (H-09); JNI array conversions
  validate null/length and guard allocation-size overflow (H-13).
- Trust-model documentation for `SecretResolver`, `SecretRef`, and
  `StdioOracle` (C-01).

## [0.5.4] - 2026-08-10

### Changed

- crates.io publishing now uses GitHub Actions OIDC trusted publishing.
