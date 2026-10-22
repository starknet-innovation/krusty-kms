//! Fee-ceiling admission and tip pinning on the deploy path (audit M-3 and
//! the October 2026 H-1 follow-up).

use super::super::deploy::{bound_deployment, pin_deployment_tip};
use super::super::StarknetRsFelt;
use krusty_kms_common::fee::{MaxBound, ResourceBoundsCeiling, DEFAULT_TIP};
use krusty_kms_domain::GatewayErrorCode;
use starknet_rust_accounts::{AccountFactory, OpenZeppelinAccountFactory};
use starknet_rust_core::types::FeeEstimate;
use starknet_rust_providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust_providers::Url;
use starknet_rust_signers::{LocalWallet, SigningKey};
use std::sync::Arc;

fn deploy_estimate() -> FeeEstimate {
    FeeEstimate {
        l1_gas_consumed: 10,
        l1_gas_price: 100,
        l2_gas_consumed: 20,
        l2_gas_price: 200,
        l1_data_gas_consumed: 30,
        l1_data_gas_price: 300,
        overall_fee: 14_000,
    }
}

fn bound(max_amount: u64, max_price_per_unit: u128) -> MaxBound {
    MaxBound {
        max_amount,
        max_price_per_unit,
    }
}

fn deploy_ceiling(l1_data_gas_price: u128) -> ResourceBoundsCeiling {
    ResourceBoundsCeiling::new(bound(15, 150), bound(30, 300), bound(45, l1_data_gas_price))
        .unwrap()
}

/// A provider that is never contacted: request building is local.
fn offline_provider() -> Arc<JsonRpcClient<HttpTransport>> {
    Arc::new(JsonRpcClient::new(HttpTransport::new(
        Url::parse("http://127.0.0.1:0").unwrap(),
    )))
}

async fn offline_factory(
) -> OpenZeppelinAccountFactory<LocalWallet, Arc<JsonRpcClient<HttpTransport>>> {
    OpenZeppelinAccountFactory::new(
        StarknetRsFelt::from(0x1234u64),
        StarknetRsFelt::from(1u64),
        LocalWallet::from(SigningKey::from_secret_scalar(StarknetRsFelt::from(7u64))),
        offline_provider(),
    )
    .await
    .unwrap()
}

// `prepared()` is synchronous and fails while the nonce, any bound, or the tip
// is unset. The nonce is normally resolved by `send`, so the tests pin it; the
// tip must come from the code under test. A request that prepares against the
// unreachable port-0 provider proves no block was fetched to estimate the tip.

#[tokio::test]
async fn bound_deployment_signs_exactly_the_admitted_bounds_and_the_ceiling_tip() {
    let factory = offline_factory().await;
    let deployment = factory
        .deploy_v3(StarknetRsFelt::ONE)
        .nonce(StarknetRsFelt::ZERO);

    let request = bound_deployment(
        deployment,
        &deploy_estimate(),
        &deploy_ceiling(450).with_max_tip(11),
    )
    .unwrap()
    .prepared()
    .unwrap()
    .get_deploy_request(true, true)
    .await
    .unwrap();

    let signed = request.resource_bounds;
    assert_eq!(signed.l1_gas.max_amount, 15);
    assert_eq!(signed.l1_gas.max_price_per_unit, 150);
    assert_eq!(signed.l2_gas.max_amount, 30);
    assert_eq!(signed.l2_gas.max_price_per_unit, 300);
    assert_eq!(signed.l1_data_gas.max_amount, 45);
    assert_eq!(signed.l1_data_gas.max_price_per_unit, 450);
    assert_eq!(request.tip, 11);
}

#[tokio::test]
async fn deployment_tip_is_pinned_without_a_ceiling_so_no_block_is_fetched() {
    let factory = offline_factory().await;
    let deployment = pin_deployment_tip(factory.deploy_v3(StarknetRsFelt::ONE), None)
        .nonce(StarknetRsFelt::ZERO)
        .l1_gas(1)
        .l1_gas_price(1)
        .l2_gas(1)
        .l2_gas_price(1)
        .l1_data_gas(1)
        .l1_data_gas_price(1);

    let request = deployment
        .prepared()
        .expect("tip pinned locally; nothing left for the RPC to resolve")
        .get_deploy_request(true, true)
        .await
        .unwrap();

    assert_eq!(request.tip, DEFAULT_TIP);
    assert_eq!(DEFAULT_TIP, 0);
}

#[tokio::test]
async fn deployment_tip_comes_from_the_ceiling_when_one_is_configured() {
    let factory = offline_factory().await;
    let deployment = pin_deployment_tip(
        factory.deploy_v3(StarknetRsFelt::ONE),
        Some(&deploy_ceiling(450).with_max_tip(5)),
    )
    .nonce(StarknetRsFelt::ZERO)
    .l1_gas(1)
    .l1_gas_price(1)
    .l2_gas(1)
    .l2_gas_price(1)
    .l1_data_gas(1)
    .l1_data_gas_price(1);

    let request = deployment
        .prepared()
        .unwrap()
        .get_deploy_request(true, true)
        .await
        .unwrap();

    assert_eq!(request.tip, 5);
}

#[tokio::test]
async fn bound_deployment_rejects_an_over_ceiling_estimate_non_retryably_naming_the_dimension() {
    let factory = offline_factory().await;
    let error = bound_deployment(
        factory.deploy_v3(StarknetRsFelt::ONE),
        &deploy_estimate(),
        &deploy_ceiling(449),
    )
    .unwrap_err();

    assert_eq!(error.code, GatewayErrorCode::InvalidRequest);
    assert!(!error.retryable);
    let message = error
        .message
        .expect("fee ceiling rejections carry a message");
    assert!(
        message.contains("l1_data_gas.max_price_per_unit 450 exceeds fee ceiling 449"),
        "{message}"
    );
}
