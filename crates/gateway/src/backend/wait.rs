//! Transaction acceptance polling: bounded waiting and receipt/status
//! classification.

use super::StarknetRsFelt;
use krusty_kms_common::KmsError;
use starknet_rust::core::types::{
    ExecutionResult, StarknetError, TransactionFinalityStatus, TransactionReceiptWithBlockInfo,
    TransactionStatus,
};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::{Provider, ProviderError};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TransactionObservation {
    Pending,
    Accepted,
    Reverted { reason: String },
}

pub(super) async fn wait_for_acceptance(
    provider: &Arc<JsonRpcClient<HttpTransport>>,
    tx_hash: StarknetRsFelt,
    poll_interval_ms: u64,
    timeout_ms: u64,
) -> Result<(), KmsError> {
    // `Instant + Duration` panics on overflow: reject absurd timeouts before
    // they reach the arithmetic (attacker-controlled via `WaitPolicy`).
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(timeout_ms))
        .ok_or_else(|| {
            KmsError::Timeout(format!(
                "wait timeout_ms={timeout_ms} exceeds the schedulable clock range"
            ))
        })?;
    let interval = Duration::from_millis(poll_interval_ms);

    loop {
        if Instant::now() >= deadline {
            return Err(KmsError::Timeout(format!(
                "transaction {} not accepted within {}ms",
                tx_hash, timeout_ms
            )));
        }

        let timeout_message = format!(
            "transaction {} not accepted within {}ms",
            tx_hash, timeout_ms
        );
        let observation = await_before_deadline(
            deadline,
            observe_transaction(provider, tx_hash),
            timeout_message,
        )
        .await?;

        match observation {
            // Never sleep past the deadline: `poll_interval_ms` is
            // caller-controlled, so a huge interval would otherwise park the
            // task far beyond the requested timeout.
            TransactionObservation::Pending => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                tokio::time::sleep(interval.min(remaining)).await
            }
            TransactionObservation::Accepted => return Ok(()),
            TransactionObservation::Reverted { reason } => {
                return Err(KmsError::TransactionReverted(format!(
                    "transaction {tx_hash:#x} reverted: {reason}"
                )))
            }
        }
    }
}

async fn await_before_deadline<T, F>(
    deadline: Instant,
    future: F,
    timeout_message: String,
) -> Result<T, KmsError>
where
    F: Future<Output = Result<T, KmsError>>,
{
    let remaining = deadline.saturating_duration_since(Instant::now());
    tokio::time::timeout(remaining, future)
        .await
        .map_err(|_| KmsError::Timeout(timeout_message))?
}

async fn observe_transaction(
    provider: &Arc<JsonRpcClient<HttpTransport>>,
    tx_hash: StarknetRsFelt,
) -> Result<TransactionObservation, KmsError> {
    match provider.get_transaction_receipt(tx_hash).await {
        Ok(receipt) => Ok(classify_receipt(&receipt)),
        Err(receipt_error) => match provider.get_transaction_status(tx_hash).await {
            Ok(status) => Ok(classify_transaction_status(&status)),
            Err(status_error) => {
                if is_transaction_hash_not_found(&receipt_error)
                    && is_transaction_hash_not_found(&status_error)
                {
                    Ok(TransactionObservation::Pending)
                } else {
                    Err(KmsError::RpcError(format!(
                        "failed to query transaction {tx_hash:#x}: receipt error: {receipt_error}; status error: {status_error}"
                    )))
                }
            }
        },
    }
}

fn classify_receipt(receipt: &TransactionReceiptWithBlockInfo) -> TransactionObservation {
    classify_execution(
        receipt.receipt.finality_status(),
        receipt.receipt.execution_result(),
    )
}

pub(super) fn classify_transaction_status(status: &TransactionStatus) -> TransactionObservation {
    match status {
        TransactionStatus::Received | TransactionStatus::Candidate => {
            TransactionObservation::Pending
        }
        TransactionStatus::PreConfirmed(execution) => {
            classify_execution(&TransactionFinalityStatus::PreConfirmed, execution)
        }
        TransactionStatus::AcceptedOnL2(execution) => {
            classify_execution(&TransactionFinalityStatus::AcceptedOnL2, execution)
        }
        TransactionStatus::AcceptedOnL1(execution) => {
            classify_execution(&TransactionFinalityStatus::AcceptedOnL1, execution)
        }
    }
}

pub(super) fn classify_execution(
    finality_status: &TransactionFinalityStatus,
    execution_result: &ExecutionResult,
) -> TransactionObservation {
    match execution_result {
        ExecutionResult::Reverted { reason } => TransactionObservation::Reverted {
            reason: reason.clone(),
        },
        ExecutionResult::Succeeded => match finality_status {
            TransactionFinalityStatus::PreConfirmed => TransactionObservation::Pending,
            TransactionFinalityStatus::AcceptedOnL2 | TransactionFinalityStatus::AcceptedOnL1 => {
                TransactionObservation::Accepted
            }
        },
    }
}

pub(super) fn is_transaction_hash_not_found(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::StarknetError(StarknetError::TransactionHashNotFound)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_flight_rpc_work_is_bounded_by_the_deadline() {
        let deadline = Instant::now() + Duration::from_millis(20);
        let result = await_before_deadline(
            deadline,
            async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(())
            },
            "bounded wait expired".to_string(),
        )
        .await;

        assert!(
            matches!(result, Err(KmsError::Timeout(message)) if message == "bounded wait expired")
        );
    }
}
