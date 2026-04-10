//! Minimal transaction builder for `ControllerWallet`.
//!
//! This builder intentionally stays generic: it batches raw Starknet calls and
//! delegates execution and fee estimation through the shared wallet boundary.

use krusty_kms_common::Result;
use krusty_kms_wallet_api::{Tx, WalletExecutor};
use starknet_rust::core::types::Call;

/// A builder that accumulates Starknet calls and executes them as one batch.
pub struct TxBuilder<'w> {
    wallet: &'w dyn WalletExecutor,
    calls: Vec<Call>,
}

impl<'w> TxBuilder<'w> {
    /// Create a new empty transaction builder.
    #[must_use]
    pub fn new(wallet: &'w dyn WalletExecutor) -> Self {
        Self {
            wallet,
            calls: Vec::new(),
        }
    }

    /// Add one call to the batch.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn add(mut self, call: Call) -> Self {
        self.calls.push(call);
        self
    }

    /// Inspect the accumulated calls.
    #[must_use]
    pub fn calls(&self) -> &[Call] {
        &self.calls
    }

    /// Estimate the fee for the batch.
    pub async fn estimate_fee(&self) -> Result<starknet_rust::core::types::FeeEstimate> {
        self.wallet.estimate_fee(self.calls.clone()).await
    }

    /// Submit the batched calls as one transaction.
    pub async fn send(self) -> Result<Tx> {
        self.wallet.execute(self.calls).await
    }
}
