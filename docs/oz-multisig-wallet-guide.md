# OpenZeppelin Multisig Wallet Guide

This guide covers how to run the multisig integration tests and how to wire the
SDK into an end-to-end wallet or CLI experience for OpenZeppelin Cairo multisig
transactions.

The implementation is split across:

- `contracts/oz_multisig`: a concrete Cairo `MultisigWallet` wrapper around
  OpenZeppelin's `MultisigComponent`.
- `krusty-kms`: deterministic deployment descriptors and constructor calldata
  for the wrapper class.
- `krusty-kms-client`: `IMultisig` call builders, transaction ID hashing,
  on-chain status queries, and trusted coordination backends.

The coordination server is not an authorization layer. It only distributes
proposals and signer status. The Starknet multisig contract remains the source
of truth for signer membership, quorum, confirmation state, and execution.

## Prerequisites

Install the normal Rust workspace toolchain, then install the Starknet tooling
used by the ignored devnet test:

```bash
scarb --version
sncast --version
starknet-devnet --version
```

For the live NATS coordinator test, use either a local `nats-server` binary or a
working Docker daemon. A local binary can be installed with Go:

```bash
go install github.com/nats-io/nats-server/v2@latest
```

## Test Matrix

Run the fast Rust tests for deterministic descriptors, calldata serialization,
transaction hashing, and coordinator behavior:

```bash
cargo test -p krusty-kms multisig
cargo test -p krusty-kms-client multisig
```

Check the client test and example targets:

```bash
cargo check -p krusty-kms-client --tests --examples
cargo check -p krusty-kms-client --features nats --tests --examples
```

Build the Cairo wrapper contract:

```bash
cd contracts/oz_multisig
scarb build
```

Run the devnet integration test from the workspace root:

```bash
cargo test -p krusty-kms-client --test oz_multisig_devnet -- --ignored --nocapture
```

That test starts `starknet-devnet`, imports a predeployed account into `sncast`,
declares and deploys `MultisigWallet`, creates a 2-of-3 multisig, proposes a
self-admin `change_quorum(3)` transaction, confirms it with two signers,
executes it, and verifies that the transaction is `Executed` and quorum is `3`.

Run the live NATS test with a local broker binary:

```bash
NATS_SERVER_BIN="$(go env GOPATH)/bin/nats-server" \
  cargo test -p krusty-kms-client --features nats --test nats_multisig_coordinator -- --ignored --nocapture
```

If `NATS_SERVER_BIN` is not set and no `nats-server` is on `PATH`, the test tries
to start `nats:2-alpine` through Docker. If neither option is available, it
prints a skip notice and exits successfully.

## Deployment Flow

Build and declare the wrapper contract:

```bash
cd contracts/oz_multisig
scarb build

sncast --account alice --accounts-file /path/to/accounts.json --wait --json \
  declare \
  --contract-name MultisigWallet \
  --package oz_multisig \
  --url http://127.0.0.1:5050
```

Use the declared class hash to build constructor calldata:

```rust
use krusty_kms::{OpenZeppelinMultisig, SaltPolicy};
use starknet_types_core::felt::Felt;

let signers = vec![alice.as_felt(), bob.as_felt(), charlie.as_felt()];
let descriptor = OpenZeppelinMultisig::from_class_hash(class_hash)
    .deployment_descriptor(2, &signers, SaltPolicy::Explicit(Felt::from(0x1234u64)))?;

assert_eq!(
    descriptor.constructor_calldata,
    vec![2.into(), 3.into(), alice.as_felt(), bob.as_felt(), charlie.as_felt()]
);
```

Deploy with `descriptor.constructor_calldata` and `descriptor.salt`. Store the
deployed multisig address in the wallet profile for future proposal, status, and
execution commands.

## Coordinator Setup

Enable the `krusty-kms-client/nats` feature and use NATS for the standard live
pub/sub path:

```rust
use krusty_kms_client::{MultisigCoordinator, NatsMultisigCoordinator};

let coordinator = NatsMultisigCoordinator::connect("nats://127.0.0.1:4222").await?;
```

Subjects are deterministic:

```text
krusty.multisig.<multisig-address-64-hex>.<transaction-id-64-hex>
```

Core NATS is live delivery, so a CLI inbox should subscribe before publishing or
before waiting for other signers. If the product needs replayable proposal
history, enable NATS JetStream for the same subject namespace or run an HTTP
gateway that persists `MultisigCoordinationMessage` payloads and republishes to
NATS.

## Transaction Lifecycle

Create a contract handle:

```rust
use krusty_kms_client::Multisig;
use krusty_kms_common::ChainId;

let multisig = Multisig::new(provider.clone(), multisig_address, ChainId::Sepolia);
```

Build the target calls and proposal:

```rust
use krusty_kms_client::{MultisigCall, MultisigCoordinationMessage};
use starknet_types_core::felt::Felt;

let call = MultisigCall::new(target_address, selector, calldata);
let proposal = multisig.proposal(
    vec![call],
    Felt::from(0x55u64),
    proposer_address,
    Some("Rotate signer".to_string()),
);

proposal.validate_transaction_id()?;
coordinator
    .publish(MultisigCoordinationMessage::Proposal(proposal.clone()))
    .await?;
```

Submit the proposal on-chain through a registered signer wallet:

```rust
let tx = multisig
    .submit_batch(&signer_wallet, &proposal.calls, proposal.salt)
    .await?;
tx.wait(wait_options).await?;
```

Other signers confirm on-chain and optionally publish signer notices:

```rust
use krusty_kms_client::MultisigSignerNotice;

let tx = multisig.confirm(&bob_wallet, proposal.transaction_id).await?;
tx.wait(wait_options).await?;

coordinator
    .publish(MultisigCoordinationMessage::Confirmation(
        MultisigSignerNotice::new(multisig_address, proposal.transaction_id, bob_address),
    ))
    .await?;
```

Once the contract reports `Confirmed`, execute the stored batch:

```rust
use krusty_kms_client::MultisigTransactionState;

let state = multisig
    .get_transaction_state(proposal.transaction_id)
    .await?;

if state == MultisigTransactionState::Confirmed {
    let tx = multisig
        .execute_batch(&executor_wallet, &proposal.calls, proposal.salt)
        .await?;
    tx.wait(wait_options).await?;
}
```

Query the chain for the final status:

```rust
let confirmations = multisig
    .get_transaction_confirmations(proposal.transaction_id)
    .await?;
let executed = multisig.is_executed(proposal.transaction_id).await?;
```

## CLI Wallet Shape

A CLI wallet can map directly onto the SDK operations:

```text
wallet multisig deploy \
  --class-hash <declared-class-hash> \
  --quorum 2 \
  --signer <alice> \
  --signer <bob> \
  --signer <charlie> \
  --salt 0x1234

wallet multisig propose \
  --multisig <address> \
  --to <target> \
  --selector <selector> \
  --calldata <felt> \
  --salt 0x55 \
  --memo "Rotate signer"

wallet multisig inbox --multisig <address> --nats nats://127.0.0.1:4222
wallet multisig submit --id <transaction-id>
wallet multisig confirm --id <transaction-id>
wallet multisig revoke --id <transaction-id>
wallet multisig execute --id <transaction-id>
wallet multisig status --id <transaction-id>
```

The wallet should persist the full proposal payload locally after `propose` or
after receiving it from the coordinator. Execution requires the original call
batch and salt, not just the transaction ID.

Recommended CLI behavior:

- `propose` computes the transaction ID locally, validates it, stores the full
  payload, and publishes `Proposal`.
- `inbox` subscribes to the NATS subject namespace and displays proposals,
  confirmations, revocations, and executions.
- `submit`, `confirm`, `revoke`, and `execute` always query the chain before
  sending a transaction so the CLI can show current state and avoid stale
  actions.
- `status` reads on-chain state first and treats coordinator messages as
  auxiliary UI context.

## Operational Notes

Protect signer private keys exactly as normal Starknet account keys. The
coordinator never needs private keys or signatures.

Use NATS authentication, TLS, and subject ACLs in shared environments. A signer
should only publish and subscribe to the multisig subject namespaces it is
allowed to observe.

Reject proposals whose `transaction_id` does not match the local
`hash_transaction_batch(calls, salt)` result. The SDK validates this before
publishing, but a wallet should also validate received messages before showing
or acting on them.

Do not treat coordinator history as final. Contract reads determine whether a
transaction exists, whether a signer confirmed it, whether quorum has been met,
and whether execution completed.
