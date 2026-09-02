//! Offline checks for the fee-ceiling glue: admission maps to typed errors and
//! pinned bounds are exactly what the signed request carries.

use super::*;
use krusty_kms_common::fee::MaxBound;
use starknet_rust::accounts::{
    Account, AccountFactory, ExecutionEncoding, OpenZeppelinAccountFactory, SingleOwnerAccount,
};
use starknet_rust::core::types::{Felt, ResourceBoundsMapping};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Url;
use starknet_rust::signers::{LocalWallet, SigningKey};
use std::sync::Arc;

fn estimate() -> FeeEstimate {
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

fn ceiling(l2_gas_amount: u64) -> ResourceBoundsCeiling {
    ResourceBoundsCeiling::new(bound(15, 150), bound(l2_gas_amount, 300), bound(45, 450)).unwrap()
}

fn scaled() -> ProposedResourceBounds {
    ProposedResourceBounds {
        l1_gas: bound(15, 150),
        l2_gas: bound(30, 300),
        l1_data_gas: bound(45, 450),
    }
}

/// A provider that is never contacted: signing and request building are local.
fn offline_provider() -> Arc<JsonRpcClient<HttpTransport>> {
    Arc::new(JsonRpcClient::new(HttpTransport::new(
        Url::parse("http://127.0.0.1:0").unwrap(),
    )))
}

fn signer() -> LocalWallet {
    LocalWallet::from(SigningKey::from_secret_scalar(Felt::from(7u64)))
}

fn assert_bounds(signed: &ResourceBoundsMapping, expected: &ProposedResourceBounds) {
    let pairs = [
        (&signed.l1_gas, expected.l1_gas),
        (&signed.l2_gas, expected.l2_gas),
        (&signed.l1_data_gas, expected.l1_data_gas),
    ];
    for (signed, expected) in pairs {
        assert_eq!(signed.max_amount, expected.max_amount);
        assert_eq!(signed.max_price_per_unit, expected.max_price_per_unit);
    }
}

#[test]
fn admitted_estimate_is_scaled_like_starknet_rs() {
    assert_eq!(admit_estimate(&estimate(), &ceiling(30)).unwrap(), scaled());
}

#[test]
fn estimate_over_ceiling_is_rejected_naming_the_dimension() {
    match admit_estimate(&estimate(), &ceiling(29)) {
        Err(KmsError::FeeEstimationFailed(message)) => assert!(
            message.contains("l2_gas.max_amount 30 exceeds fee ceiling 29"),
            "{message}"
        ),
        other => panic!("expected fee estimation failure, got {other:?}"),
    }
}

#[test]
fn out_of_range_price_is_rejected_before_admission() {
    let mut estimate = estimate();
    estimate.l1_gas_price = u128::from(u64::MAX) + 1;
    assert!(matches!(
        admit_estimate(&estimate, &ceiling(30)),
        Err(KmsError::FeeEstimationFailed(_))
    ));
}

#[tokio::test]
async fn bound_execution_signs_exactly_the_admitted_bounds() {
    let account = SingleOwnerAccount::new(
        offline_provider(),
        signer(),
        Felt::from(9u64),
        Felt::from(1u64),
        ExecutionEncoding::New,
    );
    // Nonce and tip are normally resolved by `send`; pin them so `prepared`
    // exposes the request without touching the network.
    let execution = account.execute_v3(Vec::new()).nonce(Felt::ZERO).tip(0);

    let request = bound_execution(execution, &estimate(), &ceiling(30))
        .unwrap()
        .prepared()
        .unwrap()
        .get_invoke_request(true, true)
        .await
        .unwrap();

    assert_bounds(
        &request.broadcasted_invoke_txn_v3.resource_bounds,
        &scaled(),
    );
}

#[tokio::test]
async fn bound_deployment_signs_exactly_the_admitted_bounds() {
    let factory = OpenZeppelinAccountFactory::new(
        Felt::from(0x1234u64),
        Felt::from(1u64),
        signer(),
        offline_provider(),
    )
    .await
    .unwrap();
    let deployment = factory.deploy_v3(Felt::ONE).nonce(Felt::ZERO).tip(0);

    let request = bound_deployment(deployment, &estimate(), &ceiling(30))
        .unwrap()
        .prepared()
        .unwrap()
        .get_deploy_request(true, true)
        .await
        .unwrap();

    assert_bounds(&request.resource_bounds, &scaled());
}

#[tokio::test]
async fn bound_deployment_refuses_an_estimate_over_the_ceiling() {
    let factory = OpenZeppelinAccountFactory::new(
        Felt::from(0x1234u64),
        Felt::from(1u64),
        signer(),
        offline_provider(),
    )
    .await
    .unwrap();

    let result = bound_deployment(factory.deploy_v3(Felt::ONE), &estimate(), &ceiling(29));
    assert!(matches!(result, Err(KmsError::FeeEstimationFailed(_))));
}
