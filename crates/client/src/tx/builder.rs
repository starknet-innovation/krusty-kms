//! Fluent transaction builder for batching multiple calls.

use crate::abi;
use crate::staking::Staking;
use crate::wallet::utils::core_felt_to_rs;
use krusty_kms_common::address::Address;
use krusty_kms_common::amount::Amount;
use krusty_kms_common::fee::FeeBounds;
use krusty_kms_common::token::Token;
use krusty_kms_common::Result;
use krusty_kms_wallet_api::{Tx, WalletExecutor};
use starknet_rust::core::types::Call;

/// A builder that accumulates `Call`s and sends them as a single multicall.
pub struct TxBuilder<'w> {
    wallet: &'w dyn WalletExecutor,
    calls: Vec<Call>,
}

impl<'w> TxBuilder<'w> {
    pub fn new(wallet: &'w dyn WalletExecutor) -> Self {
        Self {
            wallet,
            calls: Vec::new(),
        }
    }

    /// Add an arbitrary call.
    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, call: Call) -> Self {
        self.calls.push(call);
        self
    }

    /// Add an ERC-20 approve call.
    pub fn approve(self, token: &Token, spender: &Address, amount: &Amount) -> Self {
        let (low, high) = amount.to_u256();
        let call = Call {
            to: core_felt_to_rs(token.address.as_felt()),
            selector: *abi::erc20::APPROVE,
            calldata: vec![
                core_felt_to_rs(spender.as_felt()),
                core_felt_to_rs(low),
                core_felt_to_rs(high),
            ],
        };
        self.add(call)
    }

    /// Add an ERC-20 transfer call.
    pub fn transfer(self, token: &Token, to: &Address, amount: &Amount) -> Self {
        let (low, high) = amount.to_u256();
        let call = Call {
            to: core_felt_to_rs(token.address.as_felt()),
            selector: *abi::erc20::TRANSFER,
            calldata: vec![
                core_felt_to_rs(to.as_felt()),
                core_felt_to_rs(low),
                core_felt_to_rs(high),
            ],
        };
        self.add(call)
    }

    /// Add calls to enter a delegation pool (approve + enter).
    pub fn enter_pool(self, staking: &Staking, amount: &Amount, reward_address: &Address) -> Self {
        let calls = staking.populate_enter(amount, reward_address);
        let mut s = self;
        for call in calls {
            s = s.add(call);
        }
        s
    }

    /// Add calls to add more stake to a pool (approve + add).
    pub fn add_to_pool(self, staking: &Staking, amount: &Amount) -> Self {
        let calls = staking.populate_add(amount);
        let mut s = self;
        for call in calls {
            s = s.add(call);
        }
        s
    }

    /// Add a claim-rewards call.
    pub fn claim_rewards(self, staking: &Staking, reward_address: &Address) -> Self {
        let call = staking.populate_claim_rewards(reward_address);
        self.add(call)
    }

    /// Add an exit-intent call.
    pub fn exit_intent(self, staking: &Staking, amount: &Amount) -> Self {
        let call = staking.populate_exit_intent(amount);
        self.add(call)
    }

    /// Add an exit-action call.
    pub fn exit_pool(self, staking: &Staking) -> Self {
        let call = staking.populate_exit();
        self.add(call)
    }

    /// Inspect the accumulated calls.
    pub fn calls(&self) -> &[Call] {
        &self.calls
    }

    /// Estimate the fee for all accumulated calls.
    pub async fn estimate_fee(&self) -> Result<starknet_rust::core::types::FeeEstimate> {
        self.wallet.estimate_fee(self.calls.clone()).await
    }

    /// Execute all accumulated calls as a single transaction.
    ///
    /// Borrows rather than consumes, so a submission refused for want of an
    /// approved fee leaves the builder intact and the same calls can be retried
    /// through [`Self::send_with_bounds`]. Consuming `self` here would destroy
    /// the transaction at exactly the moment the caller needs to re-send it.
    pub async fn send(&self) -> Result<Tx> {
        self.wallet.execute(self.calls.clone()).await
    }

    /// Execute all accumulated calls within caller-approved fee bounds.
    ///
    /// The retry half of the approval loop: pair it with
    /// [`krusty_kms_common::fee::fee_approval_required_fri`] to recover the
    /// figure a refusal reported, show it, and resubmit these same calls.
    pub async fn send_with_bounds(&self, fee_bounds: &FeeBounds) -> Result<Tx> {
        self.wallet
            .execute_with_bounds(self.calls.clone(), fee_bounds)
            .await
    }
}
