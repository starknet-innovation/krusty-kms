//! Shared wallet execution contract for Starknet wallets.
//!
//! This crate keeps the transaction tracker and wallet execution trait small so
//! higher-level wallet implementations can share one stable boundary without
//! depending on each other.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use krusty_kms_common::address::Address;
use krusty_kms_common::chain::ChainId;
use krusty_kms_common::network::NetworkPreset;
use krusty_kms_common::{KmsError, Result};
use starknet_rust::core::types::StarknetError;
use starknet_rust::core::types::{
    Call, ExecutionResult, FeeEstimate, TransactionFinalityStatus, TransactionReceipt,
    TransactionReceiptWithBlockInfo, TransactionStatus,
};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::{Provider, ProviderError};
use std::sync::Arc;

type StarknetRsFelt = starknet_rust::core::types::Felt;

/// A submitted transaction that can be polled for acceptance.
pub struct Tx {
    hash: StarknetRsFelt,
    provider: Arc<JsonRpcClient<HttpTransport>>,
    network: NetworkPreset,
}

/// Smallest polling interval [`Tx::wait`] will use. A zero interval turns the
/// wait loop into an RPC flood against the provider.
pub const MIN_WAIT_INTERVAL_SECS: u64 = 1;

/// Largest timeout [`Tx::wait`] will honour (24 hours). Bounds the deadline
/// arithmetic so a caller-supplied `u64::MAX` cannot overflow the clock.
pub const MAX_WAIT_TIMEOUT_SECS: u64 = 24 * 60 * 60;

/// Options for polling a transaction receipt.
///
/// The fields stay public for compatibility; [`Tx::wait`] applies
/// [`MIN_WAIT_INTERVAL_SECS`] and [`MAX_WAIT_TIMEOUT_SECS`] to whatever it
/// receives, and [`WaitOptions::new`] rejects out-of-range values up front.
pub struct WaitOptions {
    /// Polling interval in seconds.
    pub interval_secs: u64,
    /// Maximum wait time in seconds.
    pub timeout_secs: u64,
}

impl WaitOptions {
    /// Build options that are already inside the bounds `wait` enforces.
    ///
    /// # Errors
    /// Returns `KmsError::TransactionError` if `interval_secs` is below
    /// [`MIN_WAIT_INTERVAL_SECS`] or `timeout_secs` is zero or above
    /// [`MAX_WAIT_TIMEOUT_SECS`].
    pub fn new(interval_secs: u64, timeout_secs: u64) -> Result<Self> {
        if interval_secs < MIN_WAIT_INTERVAL_SECS {
            return Err(KmsError::TransactionError(format!(
                "wait interval_secs must be at least {MIN_WAIT_INTERVAL_SECS}"
            )));
        }
        if timeout_secs == 0 || timeout_secs > MAX_WAIT_TIMEOUT_SECS {
            return Err(KmsError::TransactionError(format!(
                "wait timeout_secs must be between 1 and {MAX_WAIT_TIMEOUT_SECS}"
            )));
        }
        Ok(Self {
            interval_secs,
            timeout_secs,
        })
    }
}

impl Default for WaitOptions {
    fn default() -> Self {
        Self {
            interval_secs: 5,
            timeout_secs: 120,
        }
    }
}

/// `(interval_secs, timeout_secs)` actually used by [`Tx::wait`]: the interval
/// is raised to the floor and the timeout capped, so options assembled
/// field-by-field can neither busy-poll nor overflow the deadline.
fn effective_wait_bounds(options: &WaitOptions) -> (u64, u64) {
    (
        options.interval_secs.max(MIN_WAIT_INTERVAL_SECS),
        options.timeout_secs.min(MAX_WAIT_TIMEOUT_SECS),
    )
}

impl Tx {
    /// Create a new transaction tracker.
    #[must_use]
    pub fn new(
        hash: StarknetRsFelt,
        provider: Arc<JsonRpcClient<HttpTransport>>,
        network: NetworkPreset,
    ) -> Self {
        Self {
            hash,
            provider,
            network,
        }
    }

    /// The transaction hash.
    #[must_use]
    pub fn hash(&self) -> StarknetRsFelt {
        self.hash
    }

    /// The transaction hash as a hex string.
    #[must_use]
    pub fn hash_hex(&self) -> String {
        format!("{:#066x}", self.hash)
    }

    /// Wait for the transaction to be accepted successfully and return its receipt.
    ///
    /// # Errors
    /// Returns:
    /// - `KmsError::Timeout` if the transaction does not reach an accepted
    ///   successful receipt before the timeout expires
    /// - `KmsError::TransactionReverted` if execution reverts
    /// - `KmsError::RpcError` if the provider cannot determine transaction state
    pub async fn wait(&self, options: Option<WaitOptions>) -> Result<TransactionReceipt> {
        let (interval_secs, timeout_secs) = effective_wait_bounds(&options.unwrap_or_default());
        let deadline = tokio::time::Instant::now()
            .checked_add(tokio::time::Duration::from_secs(timeout_secs))
            .ok_or_else(|| {
                KmsError::Timeout(format!(
                    "wait deadline of {timeout_secs}s overflows the clock"
                ))
            })?;
        let interval = tokio::time::Duration::from_secs(interval_secs);

        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(KmsError::Timeout(format!(
                    "Transaction {} not accepted within {timeout_secs}s",
                    self.hash_hex()
                )));
            }

            match self.observe_receipt().await? {
                ReceiptObservation::Pending | ReceiptObservation::AcceptedWithoutReceipt => {
                    tokio::time::sleep(interval).await
                }
                ReceiptObservation::Accepted(receipt) => return Ok(receipt),
                ReceiptObservation::Reverted { reason } => {
                    return Err(KmsError::TransactionReverted(format!(
                        "transaction {} reverted: {reason}",
                        self.hash_hex()
                    )))
                }
            }
        }
    }

    /// Fetch the accepted successful transaction receipt.
    ///
    /// # Errors
    /// Returns:
    /// - `KmsError::TransactionError` if the transaction is not yet accepted
    /// - `KmsError::TransactionReverted` if execution reverts
    /// - `KmsError::RpcError` if the provider cannot determine transaction state
    pub async fn receipt(&self) -> Result<TransactionReceipt> {
        match self.observe_receipt().await? {
            ReceiptObservation::Pending => Err(KmsError::TransactionError(format!(
                "transaction {} is not yet accepted",
                self.hash_hex()
            ))),
            ReceiptObservation::AcceptedWithoutReceipt => Err(KmsError::RpcError(format!(
                "transaction {} is accepted but receipt is not yet available",
                self.hash_hex()
            ))),
            ReceiptObservation::Accepted(receipt) => Ok(receipt),
            ReceiptObservation::Reverted { reason } => Err(KmsError::TransactionReverted(format!(
                "transaction {} reverted: {reason}",
                self.hash_hex()
            ))),
        }
    }

    /// Fetch the raw transaction receipt without acceptance classification.
    ///
    /// # Errors
    /// Returns an error if the provider cannot fetch a receipt for the current
    /// transaction hash.
    pub async fn raw_receipt(&self) -> Result<TransactionReceipt> {
        let receipt = self
            .provider
            .get_transaction_receipt(self.hash)
            .await
            .map_err(|error| KmsError::TransactionError(error.to_string()))?;
        Ok(receipt.receipt)
    }

    /// Build an explorer URL for this transaction.
    #[must_use]
    pub fn explorer_url(&self) -> String {
        self.network.explorer_tx_url(&self.hash_hex())
    }

    async fn observe_receipt(&self) -> Result<ReceiptObservation> {
        observe_transaction(&self.provider, self.hash).await
    }
}

/// Shared wallet execution boundary used by higher-level client helpers.
#[async_trait]
pub trait WalletExecutor: Send + Sync {
    /// Execute a list of calls as a single transaction.
    async fn execute(&self, calls: Vec<Call>) -> Result<Tx>;

    /// Estimate the fee for a list of calls.
    async fn estimate_fee(&self, calls: Vec<Call>) -> Result<FeeEstimate>;

    /// The wallet's on-chain address.
    fn address(&self) -> &Address;

    /// The chain ID this wallet targets.
    fn chain_id(&self) -> ChainId;

    /// The network preset this wallet targets.
    fn network(&self) -> &NetworkPreset;

    /// Whether the account contract is deployed on-chain.
    async fn is_deployed(&self) -> Result<bool>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReceiptObservation {
    Pending,
    AcceptedWithoutReceipt,
    Accepted(TransactionReceipt),
    Reverted { reason: String },
}

async fn observe_transaction(
    provider: &Arc<JsonRpcClient<HttpTransport>>,
    tx_hash: StarknetRsFelt,
) -> Result<ReceiptObservation> {
    match provider.get_transaction_receipt(tx_hash).await {
        Ok(receipt) => Ok(classify_receipt(receipt)),
        Err(receipt_error) => match provider.get_transaction_status(tx_hash).await {
            Ok(status) => Ok(classify_transaction_status(status)),
            Err(status_error) => {
                if is_transaction_hash_not_found(&receipt_error)
                    && is_transaction_hash_not_found(&status_error)
                {
                    Ok(ReceiptObservation::Pending)
                } else {
                    Err(KmsError::RpcError(format!(
                        "failed to query transaction {tx_hash:#x}: receipt error: {receipt_error}; status error: {status_error}"
                    )))
                }
            }
        },
    }
}

fn classify_receipt(receipt: TransactionReceiptWithBlockInfo) -> ReceiptObservation {
    let finality_status = *receipt.receipt.finality_status();
    let execution_result = receipt.receipt.execution_result().clone();
    classify_execution(&finality_status, &execution_result, Some(receipt.receipt))
}

fn classify_transaction_status(status: TransactionStatus) -> ReceiptObservation {
    match status {
        TransactionStatus::Received | TransactionStatus::Candidate => ReceiptObservation::Pending,
        TransactionStatus::PreConfirmed(execution) => {
            classify_execution(&TransactionFinalityStatus::PreConfirmed, &execution, None)
        }
        TransactionStatus::AcceptedOnL2(execution) => {
            classify_execution(&TransactionFinalityStatus::AcceptedOnL2, &execution, None)
        }
        TransactionStatus::AcceptedOnL1(execution) => {
            classify_execution(&TransactionFinalityStatus::AcceptedOnL1, &execution, None)
        }
    }
}

fn classify_execution(
    finality_status: &TransactionFinalityStatus,
    execution_result: &ExecutionResult,
    receipt: Option<TransactionReceipt>,
) -> ReceiptObservation {
    match execution_result {
        ExecutionResult::Reverted { reason } => ReceiptObservation::Reverted {
            reason: reason.clone(),
        },
        ExecutionResult::Succeeded => match finality_status {
            TransactionFinalityStatus::PreConfirmed => ReceiptObservation::Pending,
            TransactionFinalityStatus::AcceptedOnL2 | TransactionFinalityStatus::AcceptedOnL1 => {
                match receipt {
                    Some(receipt) => ReceiptObservation::Accepted(receipt),
                    None => ReceiptObservation::AcceptedWithoutReceipt,
                }
            }
        },
    }
}

fn is_transaction_hash_not_found(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::StarknetError(StarknetError::TransactionHashNotFound)
    )
}

#[cfg(test)]
mod tests {
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
            classify_transaction_status(TransactionStatus::AcceptedOnL2(
                ExecutionResult::Succeeded,
            )),
            ReceiptObservation::AcceptedWithoutReceipt
        );
    }

    #[test]
    fn reverted_status_is_terminal() {
        assert_eq!(
            classify_transaction_status(TransactionStatus::PreConfirmed(
                ExecutionResult::Reverted {
                    reason: "constructor failed".to_string(),
                },
            )),
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
}
