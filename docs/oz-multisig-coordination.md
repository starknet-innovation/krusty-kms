# OpenZeppelin Multisig Coordination

This repo supports OpenZeppelin Cairo multisig contracts through two layers:

- `krusty-kms` builds deterministic deployment descriptors for a concrete
  `MultisigWallet` class.
- `krusty-kms-client` builds and submits `IMultisig` calls, computes the same
  transaction IDs as the contract, and defines a trusted coordination protocol.

The trusted coordinator is not an authority. It is a pub/sub server for proposal
and status messages. Every signer still submits `submit_transaction_batch`,
`confirm_transaction`, `revoke_confirmation`, or `execute_transaction_batch`
through their own Starknet account, and the contract enforces signer/quorum
rules on-chain.

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
2. The client publishes `MultisigCoordinationMessage::Proposal` to the trusted
   coordinator.
3. A registered signer submits the proposal on-chain with
   `submit_transaction_batch`.
4. Each approving signer sends `confirm_transaction(id)` on-chain and may publish
   `Confirmation` to the coordinator.

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
message payload is the stable JSON `MultisigCoordinationMessage` shape shown
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

Messages are JSON with hex-encoded felts:

```json
{
  "type": "proposal",
  "multisig": "0x0000000000000000000000000000000000000000000000000000000000000401",
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
}
```

The SDK validates proposal IDs before publishing. Consumers should still query
the chain before acting because coordinator state can lag or be incomplete.

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
