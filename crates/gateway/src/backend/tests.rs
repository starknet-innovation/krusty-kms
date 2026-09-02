use super::deploy::{
    bound_deployment, map_deploy_provider_error, map_deploy_starknet_error,
    validate_open_zeppelin_descriptor,
};
use super::rpc::{
    is_contract_not_found, is_entrypoint_not_found, map_provider_error, provider_error_message,
    provider_transport_error,
};
use super::wait::{
    classify_execution, classify_transaction_status, is_transaction_hash_not_found,
    TransactionObservation,
};
use super::StarknetRsFelt;
use krusty_kms_common::fee::{MaxBound, ResourceBoundsCeiling};
use krusty_kms_common::ChainId;
use krusty_kms_domain::{
    AccountDescriptor, DerivationPath, FeltHex, GatewayErrorCode, KeyDomain, Provenance,
};
use starknet_rust::accounts::{AccountFactory, OpenZeppelinAccountFactory};
use starknet_rust::core::types::{
    ExecutionResult, FeeEstimate, StarknetError, TransactionFinalityStatus, TransactionStatus,
};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::jsonrpc::{HttpTransportError, JsonRpcClientError, JsonRpcError};
use starknet_rust::providers::Url;
use starknet_rust::providers::{ProviderError, ProviderImplError};
use starknet_rust::signers::{LocalWallet, SigningKey};
use starknet_types_core::felt::Felt;
use std::sync::Arc;

/// Stand-in for a transport error whose `Display` leaks the request URL, the
/// way `reqwest::Error` does (`... for url (https://host/path?key=...)`).
#[derive(Debug)]
struct LeakyTransportError(&'static str);

impl std::fmt::Display for LeakyTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for LeakyTransportError {}

impl ProviderImplError for LeakyTransportError {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

const LEAKY_MESSAGE: &str =
    "error sending request for url (https://user:pw@rpc.example.com/v0_9/SECRET_TOKEN?apikey=SECRET_TOKEN)";

#[test]
fn transport_errors_are_classified_without_the_endpoint_url() {
    let error = ProviderError::Other(Box::new(LeakyTransportError(LEAKY_MESSAGE)));
    assert!(
        error.to_string().contains("SECRET_TOKEN"),
        "precondition: the upstream Display is what leaks"
    );

    let mapped = map_provider_error(error);
    assert_eq!(mapped.code, GatewayErrorCode::ProviderTransport);
    assert!(mapped.retryable);
    let message = mapped.message.expect("transport errors carry a message");
    assert_eq!(message, "provider transport error: other");
    for leaked in ["SECRET_TOKEN", "rpc.example.com", "user", "pw", "v0_9"] {
        assert!(!message.contains(leaked), "leaked {leaked:?}");
    }
}

#[test]
fn json_rpc_transport_errors_keep_only_the_numeric_code() {
    let error: ProviderError =
        JsonRpcClientError::<HttpTransportError>::JsonRpcError(JsonRpcError {
            code: -32000,
            message: "invalid api key SECRET_TOKEN".to_string(),
            data: None,
        })
        .into();

    let message = provider_error_message(&error);
    assert_eq!(message, "provider transport error: json-rpc code -32000");
    assert!(!message.contains("SECRET_TOKEN"));
}

#[test]
fn typed_provider_errors_keep_their_upstream_message() {
    assert_eq!(
        provider_error_message(&ProviderError::StarknetError(
            StarknetError::ContractNotFound
        )),
        StarknetError::ContractNotFound.to_string()
    );
    assert_eq!(
        provider_error_message(&ProviderError::RateLimited),
        "Request rate limited"
    );
    let deploy = map_deploy_provider_error(ProviderError::RateLimited);
    assert_eq!(deploy.code, GatewayErrorCode::ProviderTransport);
    assert_eq!(deploy.message.as_deref(), Some("Request rate limited"));
}

#[test]
fn deploy_transport_errors_are_redacted_too() {
    let mapped = map_deploy_provider_error(ProviderError::Other(Box::new(LeakyTransportError(
        LEAKY_MESSAGE,
    ))));
    assert_eq!(mapped.code, GatewayErrorCode::ProviderTransport);
    assert!(mapped.retryable);
    assert_eq!(
        mapped.message.as_deref(),
        Some("provider transport error: other")
    );
}

fn open_zeppelin_descriptor(public_key: Felt) -> AccountDescriptor {
    AccountDescriptor {
        address: FeltHex::from_felt(Felt::from(0xa11u64)),
        public_key: FeltHex::from_felt(public_key),
        class_hash: FeltHex::from_felt(Felt::from(0xc1a55u64)),
        salt: FeltHex::from_felt(public_key),
        constructor_calldata: vec![FeltHex::from_felt(public_key)],
        deployer_address: FeltHex::from_felt(Felt::ZERO),
        provenance: Provenance {
            chain_id: ChainId::Sepolia,
            key_domain: KeyDomain::StarknetAccount,
            derivation_path: DerivationPath {
                coin_type: 9004,
                account_index: 0,
                address_index: 0,
            },
            class_hash: None,
        },
    }
}

#[test]
fn open_zeppelin_descriptor_validation_takes_the_kms_derived_public_key() {
    let public_key = krusty_kms::stark_public_key(&Felt::from(123u64)).unwrap();
    let account = open_zeppelin_descriptor(public_key);

    assert!(validate_open_zeppelin_descriptor(&account, public_key).is_ok());

    let mismatch = validate_open_zeppelin_descriptor(&account, Felt::from(7u64)).unwrap_err();
    assert_eq!(mismatch.code, GatewayErrorCode::InvalidRequest);
    assert!(!mismatch.retryable);
}

#[test]
fn successful_preconfirmed_transactions_remain_pending() {
    assert_eq!(
        classify_execution(
            &TransactionFinalityStatus::PreConfirmed,
            &ExecutionResult::Succeeded,
        ),
        TransactionObservation::Pending
    );
}

#[test]
fn accepted_success_is_reported_as_accepted() {
    assert_eq!(
        classify_transaction_status(&TransactionStatus::AcceptedOnL2(ExecutionResult::Succeeded,)),
        TransactionObservation::Accepted
    );
}

#[test]
fn reverted_execution_is_terminal_before_acceptance() {
    assert_eq!(
        classify_transaction_status(&TransactionStatus::PreConfirmed(
            ExecutionResult::Reverted {
                reason: "constructor failed".to_string(),
            },
        )),
        TransactionObservation::Reverted {
            reason: "constructor failed".to_string(),
        }
    );
}

#[test]
fn received_and_candidate_transactions_are_pending() {
    assert_eq!(
        classify_transaction_status(&TransactionStatus::Received),
        TransactionObservation::Pending
    );
    assert_eq!(
        classify_transaction_status(&TransactionStatus::Candidate),
        TransactionObservation::Pending
    );
}

#[test]
fn transaction_hash_not_found_is_treated_as_pending_lookup_state() {
    assert!(is_transaction_hash_not_found(
        &ProviderError::StarknetError(StarknetError::TransactionHashNotFound,)
    ));
    assert!(!is_transaction_hash_not_found(&ProviderError::RateLimited));
}

#[test]
fn deploy_error_maps_typed_class_hash_failures_without_string_parsing() {
    let error = map_deploy_provider_error(ProviderError::StarknetError(
        StarknetError::ClassHashNotFound,
    ));
    assert_eq!(error.code, GatewayErrorCode::InvalidClassHash);
    assert!(!error.retryable);
}

#[test]
fn deploy_error_maps_typed_fee_failures_without_string_parsing() {
    let error = map_deploy_provider_error(ProviderError::StarknetError(
        StarknetError::InsufficientAccountBalance,
    ));
    assert_eq!(error.code, GatewayErrorCode::InsufficientFee);
    assert!(!error.retryable);
}

#[test]
fn deploy_validation_failure_still_recognizes_already_deployed_messages() {
    let error = map_deploy_starknet_error(StarknetError::ValidationFailure(
        "Requested ContractAddress has already been deployed".to_string(),
    ));
    assert_eq!(error.code, GatewayErrorCode::InvalidRequest);
    assert!(!error.retryable);
    assert_eq!(
        error.message.as_deref(),
        Some("Requested ContractAddress has already been deployed")
    );
}

#[test]
fn deploy_check_treats_only_typed_contract_not_found_as_undeployed() {
    assert!(is_contract_not_found(&ProviderError::StarknetError(
        StarknetError::ContractNotFound,
    )));
    assert!(!is_contract_not_found(&ProviderError::RateLimited));
}

#[test]
fn selector_fallback_only_triggers_on_typed_entrypoint_not_found() {
    assert!(is_entrypoint_not_found(&ProviderError::StarknetError(
        StarknetError::EntrypointNotFound,
    )));
    assert!(!is_entrypoint_not_found(&ProviderError::RateLimited));
}

#[test]
fn selector_fallback_error_keeps_primary_and_fallback_context() {
    let error = provider_transport_error(format!(
        "failed calling balance_of after typed entrypoint-not-found fallback: primary={}; fallback={}",
        ProviderError::StarknetError(StarknetError::EntrypointNotFound),
        ProviderError::RateLimited,
    ));
    assert_eq!(error.code, GatewayErrorCode::ProviderTransport);
    let message = error
        .message
        .expect("provider transport errors include a message");
    assert!(message.contains("balance_of"));
    assert!(message.contains("primary="));
    assert!(message.contains("fallback="));
}

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
