//! Hostile-RPC regression tests for the gateway deploy path.
//!
//! The canned JSON-RPC harness lives in `common/` so this file stays about the
//! properties under test rather than the plumbing.

mod common;

use common::{descriptor_for, spawn_hostile_rpc, RpcState, SharedRpcState, TEST_PRIVATE_KEY};
use krusty_kms_common::{ChainId, FeeBounds, NetworkPreset, SecretFelt, ONE_STRK_FRI};
use krusty_kms_domain::{DeployMode, GatewayErrorCode};
use krusty_kms_gateway::{GatewayBackend, StarknetGatewayBackend};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Url;
use starknet_rust::signers::SigningKey;
use starknet_types_core::felt::Felt;
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[tokio::test]
async fn hostile_gas_price_is_refused_and_not_retryable() {
    let state = Arc::new(RpcState::default());
    let url = spawn_hostile_rpc(state.clone()).await;

    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
        Url::parse(&url).expect("url"),
    )));
    let network = NetworkPreset {
        chain_id: ChainId::Sepolia,
        rpc_url: url.clone(),
        explorer_base_url: String::new(),
        name: "hostile".into(),
    };
    let backend = StarknetGatewayBackend::new(provider, network)
        .with_fee_bounds(FeeBounds::default().with_max_fee_fri(ONE_STRK_FRI));

    let signing_key = SigningKey::from_secret_scalar(
        starknet_rust::core::types::Felt::from_hex_unchecked(TEST_PRIVATE_KEY),
    );
    let private_key = SecretFelt::new(Felt::from_hex_unchecked(TEST_PRIVATE_KEY));

    let result = backend
        .deploy_open_zeppelin(
            &private_key,
            &descriptor_for(&signing_key),
            DeployMode::SubmitOnly,
        )
        .await;

    assert_eq!(
        state.submits.load(Ordering::SeqCst),
        0,
        "a deployment was signed and submitted with endpoint-dictated fees"
    );

    let error = result.expect_err("deploy must refuse an over-ceiling fee");
    assert!(
        error
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("fee approval required"),
        "error should request approval for the higher fee, got: {error:?}"
    );
    assert!(
        !error.retryable,
        "a deterministic fee refusal must not be advertised as retryable"
    );
    assert_eq!(
        error.code,
        GatewayErrorCode::InvalidRequest,
        "the caller's own bounds rejected this, not the RPC"
    );
}

#[tokio::test]
async fn approved_deployment_pins_tip_and_tracks_the_local_hash() {
    let state = Arc::new(RpcState::default());
    let url = spawn_hostile_rpc(state.clone()).await;
    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
        Url::parse(&url).expect("url"),
    )));
    let network = NetworkPreset {
        chain_id: ChainId::Sepolia,
        rpc_url: url,
        explorer_base_url: String::new(),
        name: "hostile".into(),
    };
    let backend = StarknetGatewayBackend::new(provider, network)
        .with_fee_bounds(FeeBounds::default().with_max_fee_fri(u128::MAX));
    let signing_key = SigningKey::from_secret_scalar(
        starknet_rust::core::types::Felt::from_hex_unchecked(TEST_PRIVATE_KEY),
    );
    let private_key = SecretFelt::new(Felt::from_hex_unchecked(TEST_PRIVATE_KEY));

    let result = backend
        .deploy_open_zeppelin(
            &private_key,
            &descriptor_for(&signing_key),
            DeployMode::SubmitOnly,
        )
        .await
        .expect("approved deployment should submit");

    assert_eq!(
        state.submits.load(Ordering::SeqCst),
        1,
        "expected one submission"
    );
    assert_eq!(
        state
            .submitted_tip
            .lock()
            .expect("submitted_tip lock")
            .as_ref(),
        Some(&serde_json::json!("0x0")),
        "the signed deployment did not carry the caller's zero tip"
    );
    let tx_hash = match result {
        krusty_kms_gateway::DeployExecution::Submitted { tx_hash } => tx_hash,
        other => panic!("expected submitted deployment, got {other:?}"),
    };
    // Equality against an independent oracle, not `!= 0xdead`: a merely
    // different hash would satisfy an inequality, including the query-only
    // variant that no broadcast transaction ever has.
    assert_eq!(
        tx_hash.to_felt(),
        expected_deploy_hash(&signing_key),
        "tracked hash is not the one this deployment was signed with"
    );
}

/// The fee override must be reachable using only this crate's own exports.
///
/// The tests above import `FeeBounds` from `krusty-kms-common`, which works
/// inside this workspace. An external consumer of the published gateway crate
/// has no such dependency, so without the re-export `with_fee_bounds` is public
/// but uncallable. This fails to compile if that re-export is dropped.
#[tokio::test]
async fn fee_bounds_override_is_reachable_from_this_crate() {
    use krusty_kms_gateway::{FeeBounds as GatewayFeeBounds, ONE_STRK_FRI as GATEWAY_ONE_STRK};

    let state: SharedRpcState = Arc::new(RpcState::default());
    let url = spawn_hostile_rpc(state.clone()).await;
    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
        Url::parse(&url).expect("url"),
    )));
    let network = NetworkPreset {
        chain_id: ChainId::Sepolia,
        rpc_url: url,
        explorer_base_url: String::new(),
        name: "hostile".into(),
    };

    let backend = StarknetGatewayBackend::new(provider, network)
        .with_fee_bounds(GatewayFeeBounds::default().with_max_fee_fri(5 * GATEWAY_ONE_STRK));

    assert_eq!(backend.chain_id(), ChainId::Sepolia);
}

/// The deploy-account-v3 hash the submitted deployment must carry, computed by
/// the KMS crate rather than by the submission path under test.
fn expected_deploy_hash(signing_key: &SigningKey) -> Felt {
    use krusty_kms::tx_hash::{DaMode, ResourceBounds};

    let public_key = Felt::from_bytes_be(&signing_key.verifying_key().scalar().to_bytes_be());
    let amount = |v: u64| (v as f64 * 1.5) as u64;
    let price = |v: u128| (v as f64 * 1.5) as u128;
    let l1_gas = ResourceBounds {
        max_amount: amount(0x100),
        max_price_per_unit: price(0x100),
    };
    let l2_gas = ResourceBounds {
        max_amount: amount(0x100000),
        max_price_per_unit: price(0x38d7ea4c68000),
    };
    let l1_data_gas = ResourceBounds {
        max_amount: amount(0x100),
        max_price_per_unit: price(0x100),
    };

    // The factory signs with the address derived from class hash, salt and
    // constructor calldata — not the descriptor's declared address, which this
    // test fabricates as 0xabc.
    let derived_address = krusty_kms::calculate_contract_address(
        &Felt::ZERO,
        &Felt::from_hex_unchecked("0xdef"),
        &[public_key],
        &Felt::ZERO,
    )
    .expect("derive deploy address");

    krusty_kms::compute_deploy_account_v3_hash(
        &derived_address,
        &Felt::from_hex_unchecked("0xdef"),
        &[public_key],
        &Felt::ZERO,
        &ChainId::Sepolia.as_felt(),
        &Felt::ZERO,
        0,
        &l1_gas,
        &l2_gas,
        &l1_data_gas,
        &[],
        DaMode::L1,
        DaMode::L1,
    )
}
