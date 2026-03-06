//! Integration tests for OpenZeppelin account deployment.
//!
//! These tests exercise [`deploy_oz_account`] and [`estimate_deploy_fee`]
//! against Sepolia. All tests are `#[ignore]` because they require RPC access.
//!
//! Run with:
//! ```bash
//! cargo test -p krusty-kms-client --test deploy_oz_account -- --ignored --nocapture
//! ```

use krusty_kms::{derive_keypair, OpenZeppelinAccount};
use krusty_kms_client::{create_provider, deploy_oz_account, estimate_deploy_fee, Wallet};
use krusty_kms_common::chain::ChainId;
use krusty_kms_common::network::NetworkPreset;
use starknet_rust::signers::SigningKey;
use std::sync::Arc;

/// Test mnemonic (DO NOT USE IN PRODUCTION).
const TEST_MNEMONIC: &str =
    "habit hope tip crystal because grunt nation idea electric witness alert like";

/// Sepolia RPC URL.
const SEPOLIA_RPC_URL: &str =
    "https://starknet-sepolia.g.alchemy.com/starknet/version/rpc/v0_9/B-Gw-B-hV805x00WY6hXRJc3OMqU-zxQ";

fn signing_key_from_mnemonic(index: u32) -> SigningKey {
    let keypair = derive_keypair(TEST_MNEMONIC, index, 0, None).expect("derive keypair");
    let pk_bytes = keypair.private_key.expose_secret().to_bytes_be();
    let rs_felt = starknet_rust::core::types::Felt::from_bytes_be(&pk_bytes);
    SigningKey::from_secret_scalar(rs_felt)
}

#[tokio::test]
#[ignore]
async fn test_deploy_already_deployed_returns_flag() {
    // Index 0 is the standard test account which should already be deployed.
    let provider = Arc::new(create_provider(SEPOLIA_RPC_URL).expect("create provider"));
    let signing_key = signing_key_from_mnemonic(0);
    let oz = OpenZeppelinAccount::new();
    let chain_id = ChainId::Sepolia;
    let network = NetworkPreset::sepolia();

    let result = deploy_oz_account(provider, &signing_key, &oz, chain_id, network)
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
    let oz = OpenZeppelinAccount::new();
    let chain_id = ChainId::Sepolia;
    let network = NetworkPreset::sepolia();

    let wallet = Wallet::from_signing_key(
        provider.clone(),
        signing_key.clone(),
        &oz,
        chain_id,
        network.clone(),
    )
    .expect("wallet");

    let result = deploy_oz_account(provider, &signing_key, &oz, chain_id, network)
        .await
        .expect("deploy");

    assert_eq!(
        result.address.as_felt(),
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
    let oz = OpenZeppelinAccount::new();
    let chain_id = ChainId::Sepolia;

    let estimate = estimate_deploy_fee(provider, &signing_key, &oz, chain_id)
        .await
        .expect("fee estimate");

    assert!(estimate.overall_fee > 0, "fee estimate should be non-zero");
}
