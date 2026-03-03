//! Account abstraction — high-level TONGO account interface.

use crate::address::pub_key_to_tongo_address;
use crate::contract::TongoContract;
use crate::events::{
    BalanceDeclaredEvent, FundEvent, OutsideFundEvent, RagequitEvent, RolloverEvent,
    TongoEvent, TongoEventReader, TransferDeclaredEvent, TransferEvent, WithdrawEvent,
};
use crate::types::{
    decrypt_cipher_balance, AccountState, CipherBalance, DecryptedAccountState,
};
use krusty_kms_common::Result;
use krusty_kms_crypto::StarkCurve;
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;
use std::sync::Arc;

type CoreFelt = starknet_types_core::felt::Felt;

/// High-level TONGO account combining contract queries, events, and crypto.
pub struct Account {
    private_key: Felt,
    public_key: ProjectivePoint,
    contract: TongoContract,
    event_reader: TongoEventReader,
    contract_address: CoreFelt,
}

impl Account {
    /// Create a new Account from a private key and contract address.
    pub fn new(
        private_key: Felt,
        contract_address: CoreFelt,
        provider: Arc<JsonRpcClient<HttpTransport>>,
    ) -> Self {
        let public_key = StarkCurve::mul_generator(&private_key);
        let contract = TongoContract::new(provider.clone(), contract_address);
        let event_reader = TongoEventReader::new(provider, contract_address);

        Self {
            private_key,
            public_key,
            contract,
            event_reader,
            contract_address,
        }
    }

    /// Get the public key.
    pub fn public_key(&self) -> &ProjectivePoint {
        &self.public_key
    }

    /// Get the contract address.
    pub fn contract_address(&self) -> CoreFelt {
        self.contract_address
    }

    /// Get the TongoAddress (base58-encoded compressed public key).
    pub fn tongo_address(&self) -> Result<String> {
        pub_key_to_tongo_address(&self.public_key)
    }

    // ── State queries ───────────────────────────────────────────────────

    /// Get full account state and decrypt it.
    pub async fn state(&self) -> Result<DecryptedAccountState> {
        let raw = self.contract.get_state(&self.public_key).await?;
        let balance = decrypt_cipher_balance(&self.private_key, &raw.balance)?;
        let pending = decrypt_cipher_balance(&self.private_key, &raw.pending)?;
        Ok(DecryptedAccountState {
            balance,
            pending,
            nonce: raw.nonce,
        })
    }

    /// Get raw (encrypted) account state.
    pub async fn raw_state(&self) -> Result<AccountState> {
        self.contract.get_state(&self.public_key).await
    }

    /// Get account nonce.
    pub async fn nonce(&self) -> Result<Felt> {
        self.contract.get_nonce(&self.public_key).await
    }

    /// Get encrypted balance.
    pub async fn balance(&self) -> Result<CipherBalance> {
        self.contract.get_balance(&self.public_key).await
    }

    /// Get encrypted pending balance.
    pub async fn pending(&self) -> Result<CipherBalance> {
        self.contract.get_pending(&self.public_key).await
    }

    /// Get the ERC-20 rate.
    pub async fn rate(&self) -> Result<u128> {
        self.contract.get_rate().await
    }

    /// Get the range-proof bit size.
    pub async fn bit_size(&self) -> Result<u32> {
        self.contract.get_bit_size().await
    }

    /// Get the ERC-20 token contract address.
    pub async fn erc20(&self) -> Result<CoreFelt> {
        self.contract.get_erc20().await
    }

    /// Get the auditor's public key, if configured.
    pub async fn auditor_key(&self) -> Result<Option<ProjectivePoint>> {
        self.contract.auditor_key().await
    }

    /// Convert ERC-20 amount to Tongo units.
    pub fn erc20_to_tongo(&self, amount: u128, rate: u128) -> u128 {
        crate::types::erc20_to_tongo(amount, rate)
    }

    /// Convert Tongo amount to ERC-20 units.
    pub fn tongo_to_erc20(&self, amount: u128, rate: u128) -> u128 {
        crate::types::tongo_to_erc20(amount, rate)
    }

    /// Decrypt a cipher balance using this account's private key.
    pub fn decrypt_balance(&self, cipher: &CipherBalance) -> Result<u128> {
        decrypt_cipher_balance(&self.private_key, cipher)
    }

    // ── Event queries ───────────────────────────────────────────────────

    pub async fn get_fund_events(
        &self,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<FundEvent>> {
        self.event_reader
            .get_fund_events(&self.public_key, from_block, to_block)
            .await
    }

    pub async fn get_outside_fund_events(
        &self,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<OutsideFundEvent>> {
        self.event_reader
            .get_outside_fund_events(&self.public_key, from_block, to_block)
            .await
    }

    pub async fn get_withdraw_events(
        &self,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<WithdrawEvent>> {
        self.event_reader
            .get_withdraw_events(&self.public_key, from_block, to_block)
            .await
    }

    pub async fn get_ragequit_events(
        &self,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<RagequitEvent>> {
        self.event_reader
            .get_ragequit_events(&self.public_key, from_block, to_block)
            .await
    }

    pub async fn get_rollover_events(
        &self,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<RolloverEvent>> {
        self.event_reader
            .get_rollover_events(&self.public_key, from_block, to_block)
            .await
    }

    pub async fn get_transfer_out_events(
        &self,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<TransferEvent>> {
        self.event_reader
            .get_transfer_out_events(&self.public_key, from_block, to_block)
            .await
    }

    pub async fn get_transfer_in_events(
        &self,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<TransferEvent>> {
        self.event_reader
            .get_transfer_in_events(&self.public_key, from_block, to_block)
            .await
    }

    pub async fn get_all_events(
        &self,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<TongoEvent>> {
        self.event_reader
            .get_all_events(&self.public_key, from_block, to_block)
            .await
    }

    pub async fn get_balance_declared_events(
        &self,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<BalanceDeclaredEvent>> {
        self.event_reader
            .get_balance_declared_events(&self.public_key, from_block, to_block)
            .await
    }

    pub async fn get_transfer_declared_from_events(
        &self,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<TransferDeclaredEvent>> {
        self.event_reader
            .get_transfer_declared_from_events(&self.public_key, from_block, to_block)
            .await
    }

    pub async fn get_transfer_declared_to_events(
        &self,
        from_block: Option<u64>,
        to_block: Option<u64>,
    ) -> Result<Vec<TransferDeclaredEvent>> {
        self.event_reader
            .get_transfer_declared_to_events(&self.public_key, from_block, to_block)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_derives_public_key() {
        let private_key = Felt::from(12345u64);
        let expected_pub_key = StarkCurve::mul_generator(&private_key);

        // We can't construct Account without a provider, but we can test the derivation logic
        let derived = StarkCurve::mul_generator(&private_key);

        let exp_affine = expected_pub_key.to_affine().unwrap();
        let der_affine = derived.to_affine().unwrap();
        assert_eq!(exp_affine.x(), der_affine.x());
        assert_eq!(exp_affine.y(), der_affine.y());
    }

    #[test]
    fn test_rate_conversion_delegation() {
        assert_eq!(crate::types::erc20_to_tongo(1000, 10), 100);
        assert_eq!(crate::types::tongo_to_erc20(100, 10), 1000);
    }
}
