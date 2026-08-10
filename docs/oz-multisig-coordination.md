# OpenZeppelin Multisig Coordination

This repo supports OpenZeppelin Cairo multisig contracts through two layers:

- `krusty-kms` builds deterministic deployment descriptors for a concrete
  `MultisigWallet` class.
- `krusty-kms-client` builds and submits `IMultisig` calls, computes the same
  transaction IDs as the contract, and defines the coordination protocol.

The coordinator is trusted for delivery only, never for authenticity. It is a
pub/sub server for proposal and status messages, and it is a distribution
boundary rather than an authorization boundary: a compromised coordinator can
drop, reorder, replay, or forge payloads. Every signer still submits
`submit_transaction_batch`, `confirm_transaction`, `revoke_confirmation`, or
`execute_transaction_batch` through their own Starknet account, the contract
enforces signer/quorum rules on-chain, and actor attribution is authenticated
by [signed envelopes](#signed-envelopes) rather than by the transport.

For an operator-facing walkthrough covering devnet tests, NATS tests, and a
CLI-style wallet lifecycle, see
[`oz-multisig-wallet-guide.md`](./oz-multisig-wallet-guide.md).

## Contract

`contracts/oz_multisig` wraps
`openzeppelin_governance::multisig::MultisigComponent` as a concrete
`MultisigWallet` contract.

Constructor calldata is:

```text
[quorum, signers_len, signer_0, signer_1, ...]
```

Build and declare that contract, then pass the declared class hash to:

```rust
use krusty_kms::{OpenZeppelinMultisig, SaltPolicy};

let multisig = OpenZeppelinMultisig::from_class_hash(class_hash);
let descriptor = multisig.deployment_descriptor(
    2,
    &[alice_address, bob_address, charlie_address],
    SaltPolicy::Explicit(salt),
)?;
```

## Transaction Flow

1. A signer builds a `MultisigProposal` from one or more `MultisigCall`s.
2. The client wraps `MultisigCoordinationMessage::Proposal` in a
   `SignedMultisigCoordinationMessage` (signed with the proposer's account
   key) and publishes it to the coordinator.
3. A registered signer submits the proposal on-chain with
   `submit_transaction_batch`.
4. Each approving signer sends `confirm_transaction(id)` on-chain and may publish
   a signed `Confirmation` to the coordinator.

   **Warning:** when the id came from a coordinator message, do not call
   `Multisig::confirm(id)` with it directly — the id arrives unauthenticated
   and could be forged by a compromised coordinator. Use
   `Multisig::confirm_proposal`, which recomputes the id from the proposal
   payload and binds the multisig address and chain before signing. Raw
   `confirm(id)` is only for ids obtained from a trusted source (e.g. an
   on-chain read or a locally constructed proposal).
5. Once `get_transaction_state(id)` returns `Confirmed`, any registered signer
   can send `execute_transaction_batch`.

The transaction ID is:

```text
pedersen_chain([calls_len, to, selector, calldata_len, calldata..., salt])
```

This matches OpenZeppelin's Cairo `hash_transaction_batch`.

## Coordinator Backends

The preferred live pub/sub backend is NATS, exposed by
`NatsMultisigCoordinator`. NATS gives the SDK a well-known, widely deployed
subject-based message bus instead of a bespoke socket protocol. The default
subject layout is:

```text
krusty.multisig.<chain-id>.<multisig-address-64-hex>.<transaction-id-64-hex>
```

The chain-id token (`SN_MAIN` / `SN_SEPOLIA`) namespaces subjects so a shared
coordinator cannot leak or replay messages across networks for the same
multisig/transaction-id pair.

Core NATS pub/sub is live delivery, so subscribers should call `subscribe`
before the proposal or signer notice is published. Deployments that need durable
message replay should enable NATS JetStream for the same subject namespace. The
message payload is the stable JSON `MultisigCoordinationEnvelope` shape shown
below, which can also be wrapped by gateway services using standard
CloudEvents/NATS conventions when crossing service boundaries.

```rust
use futures_util::StreamExt;
use krusty_kms_client::{MultisigCoordinator, NatsMultisigCoordinator};

let coordinator = NatsMultisigCoordinator::connect("nats://127.0.0.1:4222").await?;
let mut messages = coordinator.subscribe(&proposal.topic()).await?;

coordinator.publish(proposal_message).await?;
let received = messages.next().await.transpose()?;
```

The built-in `HttpMultisigCoordinator` remains useful for simple retained
message APIs or for gateway services that bridge HTTP clients into NATS. It
expects:

```text
POST /v1/multisig/messages
GET  /v1/multisig/messages?multisig=<addr>&transaction_id=<id>
```

Messages are JSON with hex-encoded felts. The preferred wire shape is the
version 1 signed envelope:

```json
{
  "version": 1,
  "message": {
    "type": "proposal",
    "multisig": "0x0000000000000000000000000000000000000000000000000000000000000401",
    "chain_id": "Sepolia",
    "transaction_id": "0x...",
    "calls": [
      {
        "to": "0x...",
        "selector": "0x...",
        "calldata": ["0x..."]
      }
    ],
    "salt": "0x...",
    "proposer": "0x...",
    "memo": "Increase the target counter"
  },
  "signature": ["0x...", "0x..."]
}
```

A legacy (schema version 0) payload is the bare `message` object without the
envelope; the SDK still parses it but treats it as an unauthenticated hint.

The SDK validates proposal IDs before publishing. Consumers should still query
the chain before acting because coordinator state can lag or be incomplete.

## Signed Envelopes

The coordinator is untrusted, so without authentication it can forge
`Confirmation`, `Revocation`, or `Execution` notices for any signer, and can
rewrite a proposal's `proposer`/`memo` attribution without changing the
transaction ID. Signed envelopes close that gap.

`SignedMultisigCoordinationMessage` carries the claimed actor's account
signature over a domain-separated Pedersen chain:

```text
pedersen_chain([
  'krusty-kms.multisig.notice.v1',  # domain tag (binds the schema version)
  chain_id, multisig, transaction_id,  # routing topic
  message_kind,                        # 1=proposal 2=confirmation 3=revocation 4=execution
  payload_hash,                        # kind-specific: actor (+ memo hash for proposals)
])
```

The proposal payload hash covers the proposer and the `starknet_keccak` of the
memo; `calls`/`salt` are bound transitively through `transaction_id`, which
receivers independently recompute. That recomputation is mandatory, not
advisory: because the signature does not cover `calls`/`salt` directly, a
coordinator could otherwise swap the batch while keeping the original id and
signature. Both verification entry points recompute the id before considering
the signature, so no path can attribute a tampered batch to a signer. The signature itself is a SNIP-6 felt array
(`[r, s]` for Stark-key accounts, produced by
`SignedMultisigCoordinationMessage::sign_with_stark_key`), so non-Stark account
types can carry their native signature encoding via
`SignedMultisigCoordinationMessage::new`.

Receivers authenticate a signed envelope before tallying it:

```rust
// On-chain trust path: claimed actor must be in the multisig's signer set and
// the actor's account contract must accept the signature (SNIP-6
// `is_valid_signature`). Returns the authenticated actor address.
let actor = multisig.verify_signed_message(&signed).await?;

// Offline path when the actor's Stark public key is already known and trusted.
signed.verify_with_stark_public_key(public_key)?;
```

Both on-chain reads in `verify_signed_message` are pinned to a single block
hash, so a signer removal or account upgrade landing mid-verification cannot be
observed by the membership check but not the signature check.

### What a verified envelope proves

A verified envelope proves the actor authorized *that exact message* — the
routing topic, the message kind, and the attribution fields covered by the
hash. It does **not** prove:

- **Publisher identity.** Anyone holding a copy, the coordinator included, can
  relay it.
- **Freshness or uniqueness.** A valid envelope stays valid, so the coordinator
  can replay it. Consumers that tally notices must deduplicate by
  `(actor, topic, message kind)` before counting, or one confirmation can be
  counted repeatedly.
- **On-chain success.** Chain reads stay authoritative for quorum and execution
  state; a notice is at most a hint to go read them.

### Schema versioning

The signed envelope is version 1 of the coordinator payload schema
(`MULTISIG_COORDINATION_SCHEMA_VERSION`); bare unsigned messages are version 0.
Both NATS and HTTP coordinators send and accept `MultisigCoordinationEnvelope`,
which deserializes either shape and rejects signed envelopes with an unknown
version on both the publish and receive paths.

Deserialization discriminates on the *presence* of `version`, not by trying
each shape in turn: a payload carrying `version` must be a well-formed signed
envelope or it is rejected. Otherwise a coordinator could strip authentication
— hoisting `signature` to the top level, or setting an unsupported `version` —
and have the result silently accepted as an unsigned legacy hint.

Any future schema bump must also change the domain tag inside the signing hash
so signatures can never validate across versions.

## Integration Tests

The ignored devnet test declares and deploys the wrapper contract, builds a
2-of-3 multisig, submits a self-admin quorum change, confirms it with two
signers, executes it, and verifies the final on-chain state:

```bash
cargo test -p krusty-kms-client --test oz_multisig_devnet -- --ignored --nocapture
```

The live NATS test starts a local broker through `NATS_SERVER_BIN` or Docker and
verifies `NatsMultisigCoordinator` subscribe/publish delivery:

```bash
NATS_SERVER_BIN=/path/to/nats-server \
  cargo test -p krusty-kms-client --test nats_multisig_coordinator -- --ignored --nocapture
```
