use super::deploy::{map_deploy_provider_error, map_deploy_starknet_error};
use super::rpc::{is_contract_not_found, is_entrypoint_not_found, provider_transport_error};
use super::wait::{
    classify_execution, classify_transaction_status, is_transaction_hash_not_found,
    TransactionObservation,
};
use krusty_kms_domain::GatewayErrorCode;
use starknet_rust::core::types::{
    ExecutionResult, StarknetError, TransactionFinalityStatus, TransactionStatus,
};
use starknet_rust::providers::ProviderError;

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
