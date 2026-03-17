# Starknet Client

Starknet RPC client for interacting with TONGO contracts on Starknet.

## ✅ Implemented Features

### Core Infrastructure
- ✅ **Starknet RPC provider creation** - JSON-RPC client setup
- ✅ **Account address derivation** - OpenZeppelin account address calculation
- ✅ **ElGamal decryption** - Decrypt cipher balances from chain
- ✅ **Proof generation** - Full parity with TypeScript for Fund, Transfer, Rollover, Withdraw
- ✅ **Integration test skeleton** - Complete flow documentation with TypeScript parity

### Key Management
- ✅ **BIP-44 key derivation** - TONGO coin type 5454 and Starknet coin type 9004
- ✅ **Public key derivation** - Elliptic curve scalar multiplication
- ✅ **Account address calculation** - Pedersen hash + Starknet Keccak

### Cryptographic Primitives
- ✅ **Proof of Exponentiation (PoE)** - Schnorr-like proofs for balances
- ✅ **Proof of Exponentiation 2 (PoE2)** - Okamoto's protocol for rollovers
- ✅ **ElGamal encryption** - Homomorphic encryption for transfers
- ✅ **Fiat-Shamir challenges** - Non-interactive proof generation

## 🚧 To Be Implemented

The following components require integration with the live Starknet network:

1. **RPC State Querying** - Fetch encrypted balances from TONGO contract
2. **Transaction Signing** - Sign and submit transactions using starknet-rust
3. **Calldata Serialization** - Convert Rust proofs to Cairo calldata format
4. **ERC20 Approve Flow** - Token approval before fund operations
5. **State Verification** - Query and decrypt state after transactions

## Account Derivation

The crate supports deriving Starknet account contract addresses using the standard contract address calculation formula:

```rust
use krusty_kms::{derive_keypair, derive_oz_account_address, ChainId, OpenZeppelinAccount};

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

## Next Steps

To complete the integration with Starknet:

### 1. Add TONGO Contract Interactions

Create a `TongoClient` struct that wraps the starknet provider and provides high-level methods:

```rust
pub struct TongoClient {
    provider: JsonRpcClient<HttpTransport>,
    contract_address: Felt,
}

impl TongoClient {
    pub async fn fund(&self, account: &TongoAccount, amount: u128) -> Result<TransactionHash>;
    pub async fn transfer(&self, account: &TongoAccount, to: &ProjectivePoint, amount: u128) -> Result<TransactionHash>;
    pub async fn rollover(&self, account: &TongoAccount) -> Result<TransactionHash>;
    pub async fn withdraw(&self, account: &TongoAccount, to: &Felt, amount: u128) -> Result<TransactionHash>;
    pub async fn get_state(&self, public_key: &ProjectivePoint) -> Result<TongoState>;
}
```

### 2. Implement Account Signer

Add utilities for signing transactions using derived keys:

```rust
use starknet_rust::accounts::{Account, SingleOwnerAccount};
use starknet_rust::signers::{LocalWallet, SigningKey};

pub fn create_signer(
    provider: JsonRpcClient<HttpTransport>,
    private_key: &Felt,
    address: &Felt,
    chain_id: Felt,
) -> SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet> {
    let signer = LocalWallet::from(SigningKey::from_secret_scalar(private_key));
    SingleOwnerAccount::new(provider, signer, *address, chain_id)
}
```

### 3. Add Integration Tests

Create tests that replicate the TypeScript `tongo-sepolia.test.ts`:

```rust
#[tokio::test]
#[ignore] // Requires Sepolia testnet access
async fn test_fund_operation() {
    let provider = create_provider(SEPOLIA_RPC_URL);
    let tongo_client = TongoClient::new(provider, TONGO_CONTRACT_ADDRESS);

    // Derive TONGO keypair
    let keypair = derive_keypair(MNEMONIC, 0, 0, None)?;
    let account = TongoAccount::from_private_key(keypair.private_key, TONGO_CONTRACT_ADDRESS)?;

    // Check initial balance
    let state_before = tongo_client.get_state(&account.keypair.public_key).await?;

    // Fund operation
    let tx_hash = tongo_client.fund(&account, 1).await?;
    provider.wait_for_transaction(tx_hash).await?;

    // Verify balance increased
    let state_after = tongo_client.get_state(&account.keypair.public_key).await?;
    assert_eq!(state_after.balance, state_before.balance + 1);
}
```

## OpenZeppelin Account Class Hash

The canonical deployment flow resolves the latest manifest-backed OpenZeppelin
account class hash for the target network. Today the checked-in latest entry is:

```
0x01d1777db36cdd06dd62cfde77b1b6ae06412af95d57a13dc40ac77b8a702381
```

The older TypeScript parity fixtures in this repo still use their historical
explicit class hash so those external integration tests remain reproducible.

## TONGO Contract Address (Sepolia)

```
0x00b4cca30f0f641e01140c1c388f55641f1c3fe5515484e622b6cb91d8cee585
```

## Related Crates

- `krusty-kms`: Key derivation and account address calculation
- `krusty-kms-sdk`: TONGO operation proof generation
- `krusty-kms-crypto`: Cryptographic primitives (PoE, PoE2, ElGamal)
