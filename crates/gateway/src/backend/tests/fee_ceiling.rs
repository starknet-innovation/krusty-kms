//! Fee-ceiling admission on the deploy path (audit M-3).

use super::super::deploy::bound_deployment;
use super::super::StarknetRsFelt;
use krusty_kms_common::fee::{MaxBound, ResourceBoundsCeiling};
use krusty_kms_domain::GatewayErrorCode;
use starknet_rust::accounts::{AccountFactory, OpenZeppelinAccountFactory};
use starknet_rust::core::types::FeeEstimate;
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Url;
use starknet_rust::signers::{LocalWallet, SigningKey};
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

#[tokio::test]
async fn bound_deployment_signs_exactly_the_admitted_bounds() {
    let factory = offline_factory().await;
    // Nonce and tip are normally resolved by `send`; pin them so `prepared`
    // exposes the request without touching the network.
    let deployment = factory
        .deploy_v3(StarknetRsFelt::ONE)
        .nonce(StarknetRsFelt::ZERO)
        .tip(0);

    let request = bound_deployment(deployment, &deploy_estimate(), &deploy_ceiling(450))
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
