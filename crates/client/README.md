# Starknet Client

Focused Starknet wallet, deployment, and Tongo protocol client helpers.

## Public API

This crate’s public API focuses on:

- provider construction
- wallet execution and transaction tracking
- OpenZeppelin account deployment helpers
- OpenZeppelin multisig call builders and trusted coordination messages
- Tongo account/contract access
- Tongo call builders and balance decryption

Broader ecosystem helpers such as ERC-20 token metadata, staking, and DeFi
adapters remain implementation details.

## Account Derivation

The crate supports deriving Starknet account contract addresses using the standard contract address calculation formula:

```rust
use krusty_kms::{derive_keypair, derive_oz_account_address, OpenZeppelinAccount};
use krusty_kms_common::ChainId;

// Derive a keypair from mnemonic
let keypair = derive_keypair(mnemonic, index, account_index, None)?;

// Get the public key x-coordinate
let affine = keypair.public_key.to_affine()?;
let public_key_x = affine.x();

// Resolve the latest manifest-backed OZ class hash for Sepolia
let class_hash = OpenZeppelinAccount::latest(ChainId::Sepolia)?.class_hash();
let account_address = derive_oz_account_address(&public_key_x, &class_hash, None)?;
```

## Testing

Run the account derivation tests:

```bash
cargo test -p krusty-kms-client --test account_derivation
```

## OpenZeppelin Account Class Hash

The canonical deployment flow resolves the latest manifest-backed OpenZeppelin
account class hash for the target network. Today the checked-in latest entry is:

```
0x01d1777db36cdd06dd62cfde77b1b6ae06412af95d57a13dc40ac77b8a702381
```

The older TypeScript parity fixtures in this repo still use their historical
explicit class hash so those external integration tests remain reproducible.

## OpenZeppelin Multisig

The client exposes `Multisig` for OpenZeppelin Cairo multisig contracts:

- `populate_submit_batch`, `populate_confirm`, `populate_revoke`, and
  `populate_execute_batch` build exact `IMultisig` calls.
- `hash_transaction_batch` computes the same Pedersen transaction ID as the
  contract.
- `MultisigCoordinator` defines the trusted pub/sub boundary used to distribute
  proposals and signer status.
- `NatsMultisigCoordinator` provides the standard live pub/sub backend; the HTTP
  coordinator is available for simple retained-message services.

See [`docs/oz-multisig-coordination.md`](../../docs/oz-multisig-coordination.md),
[`docs/oz-multisig-wallet-guide.md`](../../docs/oz-multisig-wallet-guide.md),
and `cargo run -p krusty-kms-client --example oz_multisig_coordination`.

## Tongo Contract Address (Sepolia)

```
0x00b4cca30f0f641e01140c1c388f55641f1c3fe5515484e622b6cb91d8cee585
```

## Related Crates

- `krusty-kms`: Key derivation and account address calculation
- `krusty-kms-sdk`: Tongo operation proof generation
- `krusty-kms-crypto`: Cryptographic primitives (PoE, PoE2, ElGamal)
