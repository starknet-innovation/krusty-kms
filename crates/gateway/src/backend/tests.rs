use super::deploy::{
    map_deploy_provider_error, map_deploy_starknet_error, validate_open_zeppelin_descriptor,
};
use super::rpc::{
    is_contract_not_found, is_entrypoint_not_found, map_provider_error, provider_error_message,
    provider_transport_error,
};
use super::wait::{
    classify_execution, classify_transaction_status, is_transaction_hash_not_found,
    TransactionObservation,
};
use krusty_kms_common::ChainId;
use krusty_kms_domain::{
    AccountDescriptor, DerivationPath, FeltHex, GatewayErrorCode, KeyDomain, Provenance,
};
use starknet_rust::core::types::{
    ExecutionResult, StarknetError, TransactionFinalityStatus, TransactionStatus,
};
use starknet_rust::providers::jsonrpc::{HttpTransportError, JsonRpcClientError, JsonRpcError};
use starknet_rust::providers::{ProviderError, ProviderImplError};
use starknet_types_core::felt::Felt;

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
