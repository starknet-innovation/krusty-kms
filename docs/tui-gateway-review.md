# Issue #12 Review: TUI-First Gateway Architecture

Architecture review mapping issue `#12` requirements to the current repository.

## What Already Exists

- Canonical OpenZeppelin derive/deploy logic:
  - `crates/kms/src/account_class.rs` exposes `OzDeploymentDescriptor`
  - `crates/client/src/wallet/deploy.rs` uses the same canonical path for address derivation and deploy submission
- Deterministic derive/sign/prove primitives:
  - `crates/kms` for key derivation and account descriptors
  - `crates/sdk` for Tongo proof generation
  - `crates/client` for calldata assembly, wallet execution, and transaction waiting
- Some runtime conveniences already exist:
  - wallet deployment-status caching in `crates/client/src/wallet/mod.rs`
  - typed `Tx` waiting in `crates/client/src/tx/mod.rs`
  - ERC-20 balance and nonce queries in `crates/client`
- Nostr key derivation already exists.

## Main Gaps Against Issue #12

Identified gaps:

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

This slice adds:

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

## Scope Boundary

Not included:

- a long-lived gateway daemon
- keystore persistence
- telemetry hooks

Those remain runtime and product-policy concerns beyond the current stdio V1 transport.
