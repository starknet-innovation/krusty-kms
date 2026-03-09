//! Transaction tracking and receipt waiting.

pub mod builder;
pub mod hash;

pub use builder::TxBuilder;

use krusty_kms_common::network::NetworkPreset;
use krusty_kms_common::{KmsError, Result};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Provider;
use std::sync::Arc;

type StarknetRsFelt = starknet_rust::core::types::Felt;

/// A submitted transaction that can be polled for acceptance.
pub struct Tx {
    hash: StarknetRsFelt,
    provider: Arc<JsonRpcClient<HttpTransport>>,
    network: NetworkPreset,
}

/// Options for polling a transaction receipt.
pub struct WaitOptions {
    /// Polling interval in seconds (default 5).
    pub interval_secs: u64,
    /// Maximum wait time in seconds (default 120).
    pub timeout_secs: u64,
}

impl Default for WaitOptions {
    fn default() -> Self {
        Self {
            interval_secs: 5,
            timeout_secs: 120,
        }
    }
}

impl Tx {
    /// Create a new `Tx` tracker.
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
    pub fn hash(&self) -> StarknetRsFelt {
        self.hash
    }

    /// The transaction hash as a hex string.
    pub fn hash_hex(&self) -> String {
        format!("{:#066x}", self.hash)
    }

    /// Wait for the transaction to be accepted on L2.
    pub async fn wait(
        &self,
        options: Option<WaitOptions>,
    ) -> Result<starknet_rust::core::types::TransactionReceipt> {
        let opts = options.unwrap_or_default();
        let deadline =
            tokio::time::Instant::now() + tokio::time::Duration::from_secs(opts.timeout_secs);
        let interval = tokio::time::Duration::from_secs(opts.interval_secs);

        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(KmsError::Timeout(format!(
                    "Transaction {} not accepted within {}s",
                    self.hash_hex(),
                    opts.timeout_secs
                )));
            }

            match self.receipt().await {
                Ok(receipt) => return Ok(receipt),
                Err(_) => {
                    tokio::time::sleep(interval).await;
                }
            }
        }
    }

    /// Fetch the transaction receipt (returns error if not yet available).
    pub async fn receipt(&self) -> Result<starknet_rust::core::types::TransactionReceipt> {
        let receipt = self
            .provider
            .get_transaction_receipt(self.hash)
            .await
            .map_err(|e| KmsError::TransactionError(e.to_string()))?;

        use starknet_rust::core::types::TransactionReceiptWithBlockInfo;
        let TransactionReceiptWithBlockInfo { receipt, .. } = receipt;
        Ok(receipt)
    }

    /// Build a Voyager explorer URL for this transaction.
    pub fn explorer_url(&self) -> String {
        self.network.explorer_tx_url(&self.hash_hex())
    }
}
