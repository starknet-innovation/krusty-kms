//! Integration tests for OpenZeppelin account deployment.
//!
//! These tests exercise [`deploy_oz_account`] and [`estimate_deploy_fee`]
//! against Sepolia. All tests are `#[ignore]` because they require RPC access.
//!
//! Run with:
//! ```bash
//! cargo test -p krusty-kms-client --test deploy_oz_account -- --ignored --nocapture
//! ```

use krusty_kms::{
    derive_keypair_with_coin_type, OpenZeppelinAccount, SaltPolicy, STARKNET_COIN_TYPE,
};
use krusty_kms_client::{create_provider, deploy_oz_account, estimate_deploy_fee, Wallet};
use krusty_kms_common::chain::ChainId;
use krusty_kms_common::network::NetworkPreset;
use starknet_rust::signers::SigningKey;
use starknet_types_core::felt::Felt;
use std::sync::Arc;

/// Test mnemonic (DO NOT USE IN PRODUCTION).
const TEST_MNEMONIC: &str =
    "habit hope tip crystal because grunt nation idea electric witness alert like";

/// Sepolia RPC URL.
const SEPOLIA_RPC_URL: &str = "https://api.cartridge.gg/x/starknet/sepolia";

/// Legacy class hash used by the long-lived TypeScript Sepolia fixture accounts.
///
/// This is intentionally explicit: it exercises the already-deployed branch
/// without pretending that the latest OZ preset resolves to the same address.
const LEGACY_TONGO_FIXTURE_CLASS_HASH: &str =
    "0x05b4b537eaa2399e3aa99c4e2e0208ebd6c71bc1467938cd52c798c601e43564";

fn signing_key_from_mnemonic(index: u32) -> SigningKey {
    let keypair = derive_keypair_with_coin_type(TEST_MNEMONIC, index, 0, STARKNET_COIN_TYPE, None)
        .expect("derive starknet keypair");
    let pk_bytes = keypair.private_key.expose_secret().to_bytes_be();
    let rs_felt = starknet_rust::core::types::Felt::from_bytes_be(&pk_bytes);
    SigningKey::from_secret_scalar(rs_felt)
}

#[tokio::test]
#[ignore]
async fn test_deploy_already_deployed_returns_flag() {
    // Index 0 is a legacy external fixture account that is already deployed.
    let provider = Arc::new(create_provider(SEPOLIA_RPC_URL).expect("create provider"));
    let signing_key = signing_key_from_mnemonic(0);
    let chain_id = ChainId::Sepolia;
    let oz = OpenZeppelinAccount::from_class_hash(
        Felt::from_hex(LEGACY_TONGO_FIXTURE_CLASS_HASH).expect("legacy class hash"),
    );
    let network = NetworkPreset::sepolia();

    let result = deploy_oz_account(
        provider,
        &signing_key,
        &oz,
        SaltPolicy::Zero,
        chain_id,
        network,
    )
    .await
    .expect("deploy_oz_account should not error for already-deployed account");

    assert!(result.already_deployed, "expected already_deployed = true");
    assert!(result.tx.is_none(), "expected no tx for already-deployed");
}

#[tokio::test]
#[ignore]
async fn test_descriptor_address_matches_wallet_address() {
    let provider = Arc::new(create_provider(SEPOLIA_RPC_URL).expect("create provider"));
    let signing_key = signing_key_from_mnemonic(0);
    let chain_id = ChainId::Sepolia;
    let oz = OpenZeppelinAccount::latest(chain_id).expect("resolve latest oz account");
    let network = NetworkPreset::sepolia();

    let wallet = Wallet::from_signing_key(
        provider.clone(),
        signing_key.clone(),
        &oz,
        SaltPolicy::PublicKey,
        chain_id,
        network.clone(),
    )
    .expect("wallet");

    let verifying_key = signing_key.verifying_key();
    let public_key_rs = verifying_key.scalar();
    let public_key_bytes = public_key_rs.to_bytes_be();
    let public_key_core = Felt::from_bytes_be(&public_key_bytes);
    let descriptor = oz
        .deployment_descriptor(&public_key_core, SaltPolicy::PublicKey)
        .expect("deployment descriptor");

    assert_eq!(
        descriptor.address,
        wallet.address().as_felt(),
        "descriptor-derived address must match Wallet address"
    );
}

#[tokio::test]
#[ignore]
async fn test_estimate_deploy_fee_returns_nonzero() {
    // Use a high index so the account is very unlikely to be deployed.
    let provider = Arc::new(create_provider(SEPOLIA_RPC_URL).expect("create provider"));
    let signing_key = signing_key_from_mnemonic(9999);
    let chain_id = ChainId::Sepolia;
    let oz = OpenZeppelinAccount::latest(chain_id).expect("resolve latest oz account");

    let estimate =
        estimate_deploy_fee(provider, &signing_key, &oz, SaltPolicy::PublicKey, chain_id)
            .await
            .expect("fee estimate");

    assert!(estimate.overall_fee > 0, "fee estimate should be non-zero");
}
