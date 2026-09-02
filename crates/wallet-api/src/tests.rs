use super::{
    classify_transaction_status, effective_wait_bounds, is_transaction_hash_not_found,
    ReceiptObservation, WaitOptions, MAX_WAIT_TIMEOUT_SECS, MIN_WAIT_INTERVAL_SECS,
};
use starknet_rust::core::types::{ExecutionResult, StarknetError, TransactionStatus};
use starknet_rust::providers::ProviderError;

#[test]
fn zero_interval_is_raised_to_the_floor() {
    let options = WaitOptions {
        interval_secs: 0,
        timeout_secs: 10,
    };
    assert_eq!(
        effective_wait_bounds(&options),
        (MIN_WAIT_INTERVAL_SECS, 10)
    );
}

#[test]
fn max_timeout_is_capped_and_the_deadline_never_overflows() {
    let options = WaitOptions {
        interval_secs: 5,
        timeout_secs: u64::MAX,
    };
    let (_, timeout_secs) = effective_wait_bounds(&options);
    assert_eq!(timeout_secs, MAX_WAIT_TIMEOUT_SECS);
    // The unbounded value panicked in `Instant + Duration`; the capped one
    // must always fit.
    assert!(tokio::time::Instant::now()
        .checked_add(tokio::time::Duration::from_secs(timeout_secs))
        .is_some());
}

#[test]
fn new_rejects_out_of_range_options() {
    assert!(WaitOptions::new(0, 10).is_err());
    assert!(WaitOptions::new(1, 0).is_err());
    assert!(WaitOptions::new(1, MAX_WAIT_TIMEOUT_SECS + 1).is_err());
    let accepted = WaitOptions::new(MIN_WAIT_INTERVAL_SECS, MAX_WAIT_TIMEOUT_SECS).unwrap();
    assert_eq!(
        (accepted.interval_secs, accepted.timeout_secs),
        (MIN_WAIT_INTERVAL_SECS, MAX_WAIT_TIMEOUT_SECS)
    );
}

#[test]
fn accepted_status_without_receipt_is_not_reported_as_complete_receipt() {
    assert_eq!(
        classify_transaction_status(TransactionStatus::AcceptedOnL2(ExecutionResult::Succeeded,)),
        ReceiptObservation::AcceptedWithoutReceipt
    );
}

#[test]
fn reverted_status_is_terminal() {
    assert_eq!(
        classify_transaction_status(TransactionStatus::PreConfirmed(ExecutionResult::Reverted {
            reason: "constructor failed".to_string(),
        },)),
        ReceiptObservation::Reverted {
            reason: "constructor failed".to_string(),
        }
    );
}

#[test]
fn tx_hash_not_found_is_the_only_pending_lookup_error() {
    assert!(is_transaction_hash_not_found(
        &ProviderError::StarknetError(StarknetError::TransactionHashNotFound,)
    ));
    assert!(!is_transaction_hash_not_found(&ProviderError::RateLimited));
}

/// Codex review: an interval longer than the timeout must not sleep past the
/// deadline, and `new` must reject it up front.
#[test]
fn interval_is_capped_by_the_timeout() {
    let options = WaitOptions {
        interval_secs: 86_400,
        timeout_secs: 1,
    };
    assert_eq!(effective_wait_bounds(&options), (1, 1));
    let huge = WaitOptions {
        interval_secs: u64::MAX,
        timeout_secs: u64::MAX,
    };
    assert_eq!(
        effective_wait_bounds(&huge),
        (MAX_WAIT_TIMEOUT_SECS, MAX_WAIT_TIMEOUT_SECS)
    );
    assert!(WaitOptions::new(2, 1).is_err());
    assert!(WaitOptions::new(1, 1).is_ok());
}
