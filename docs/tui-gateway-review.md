# Issue #12 Review: TUI-First Gateway Architecture

This review maps the requirements in GitHub issue `#12` onto the current repository and records the smallest semantics-preserving foundation worth landing first.

## What Already Exists

The repository already contains several strong building blocks:

- Canonical OpenZeppelin derive/deploy logic:
  - `crates/kms/src/account_class.rs` exposes `OzDeploymentDescriptor`
  - `crates/client/src/wallet/deploy.rs` uses the same canonical path for address derivation and deploy submission
- Deterministic derive/sign/prove primitives:
  - `crates/kms` for key derivation and account descriptors
  - `crates/sdk` for TONGO proof generation
  - `crates/client` for calldata assembly, wallet execution, and transaction waiting
- Some runtime conveniences already exist:
  - wallet deployment-status caching in `crates/client/src/wallet/mod.rs`
  - typed `Tx` waiting in `crates/client/src/tx/mod.rs`
  - ERC-20 balance and nonce queries in `crates/client`
- Nostr key derivation already exists.

## Main Gaps Against Issue #12

The issue is primarily about integration architecture, not missing cryptographic correctness. The largest gaps are:

1. No pure integration contract crate.
   Current crates expose useful primitives, but integrators still need to invent their own request/result/status/error envelopes.

2. No unified typed runtime lifecycle.
   There is no common `OperationState` contract spanning derive, deploy, sign, prove, and query flows.

3. No protocol-ready canonical hex contract.
   Address normalization is handled in places, but there is no single serializable hex type for addresses, class hashes, salts, tx hashes, and nonce payloads.

4. No first-class snapshot/query API surface.
   The client crate can query the underlying pieces, but the TUI-facing “account snapshot” contract does not exist yet.

5. Error taxonomy is still mostly library-internal.
   `KmsError` is useful for Rust callers, but it is not yet shaped as a machine-facing transport contract with explicit retryability and transport/cache semantics.

## What Landed In This Slice

To facilitate the issue without prematurely locking in a daemon/runtime design, this slice adds:

- `crates/domain`
  - package name: `krusty-kms-domain`
  - pure, serializable integration-domain types
  - no I/O, no async runtime, no filesystem, no clocks
- canonical `FeltHex` normalization
  - ensures `0xabc` and `0x0abc` normalize identically
  - intended for protocol-stable addresses, class hashes, salts, tx hashes, and nonces
- foundational TUI/gateway contracts
  - derivation request/descriptor types
  - deployment status types
  - signing request/domain types
  - cache policy + cache metadata types
  - account snapshot request/result types
  - operation lifecycle + structured gateway error types

This foundation is now paired with a small runtime gateway crate:

- `crates/gateway`
  - `derive_account`, `check_deployment`, `deploy_account`, `sign`, and `query_account_snapshot`
  - explicit `SecretResolver`, `GatewayBackend`, and `Clock` boundaries
  - in-memory bounded snapshot cache with `active` vs `background` stale behavior
  - tracked `OperationStatus` lifecycle for derive/deploy/sign/query flows

And a first transport layer now exists on top:

- `crates/oracle`
  - stdio JSONL protocol V1
  - versioned request/response envelopes
  - fixture-backed golden tests for stable wire compatibility
  - typed `get_operation_status` lookup
  - no embedded keystore or daemon policy

## Why This Was The Right First Step

The issue proposes a `domain -> core -> gateway -> adapters -> oracle` stack.

The highest-risk mistake would be to implement `gateway` or `oracle` first and then discover that the request/result/error model is wrong. That would force either:

- incompatible protocol churn, or
- a long-lived transport surface that encodes accidental assumptions.

By stabilizing the pure domain contracts first, we preserve these invariants:

- no runtime policy leaks into the type system
- canonical hex formatting is defined once
- retryability and failure categories are explicit
- later stdio/socket transports can share one typed schema

## What This Now Covers

This slice now includes explicit multi-domain signing paths:

- `crates/kms`
  - deterministic BIP-340 Nostr event signing over 32-byte event ids
  - deterministic Stark ECDSA signing over caller-supplied felts
- `crates/domain`
  - typed `SignRequest` variants that make invalid key/domain combinations unrepresentable
  - typed `SignResult`
  - canonical byte-hex payload/result values for non-felt material
- `crates/gateway`
  - explicit `sign(...)` flow with per-domain validation at the boundary
- `crates/oracle`
  - `sign` command in stdio V1
  - checked-in request/response golden fixtures for both Nostr and Stark result shapes

## Recommended Next Implementation Order

1. Extend the gateway/oracle from request/response methods to optional event subscription or request dedupe if the TUI needs it.

2. Add any further signing family only once its wire/result contract is equally explicit.
   The current API now distinguishes Stark ECDSA and Nostr BIP-340 result shapes directly.

## Suggested Acceptance Tests

- property tests for `FeltHex` normalization invariants
- unit tests for deterministic Nostr BIP-340 signing and verification
- `derive -> deployment descriptor -> deploy` consistency tests
- snapshot contract tests with a fake cache clock
- protocol golden tests for stdio V1 request/response compatibility

## Scope Boundary

This review deliberately does **not** add:

- a long-lived gateway daemon
- keystore persistence
- telemetry hooks

Those remain runtime and product-policy concerns beyond the current stdio V1 transport.
