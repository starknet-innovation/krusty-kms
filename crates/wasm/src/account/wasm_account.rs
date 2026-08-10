//! The [`WasmAccount`] wrapper around the SDK Tongo account.

use super::helpers::{decrypted_point_to_wasm, parse_ciphertext, parse_felt, parse_u128_decimal};
use crate::error::from_sdk_result;
use crate::types::{WasmAccountState, WasmCiphertext, WasmDecryptedPoint};
use wasm_bindgen::prelude::*;

/// WASM-accessible Tongo account.
///
/// Wraps the internal SDK account with JavaScript-friendly methods.
/// Handles key management and state tracking for confidential transactions.
#[wasm_bindgen]
pub struct WasmAccount {
    pub(crate) inner: krusty_kms_sdk::TongoAccount,
}

#[wasm_bindgen]
impl WasmAccount {
    /// Create a new account from a BIP-39 mnemonic phrase.
    ///
    /// # Arguments
    /// * `mnemonic` - 12 or 24 word BIP-39 mnemonic
    /// * `address_index` - HD wallet address index (default: 0)
    /// * `account_index` - HD wallet account index (default: 0)
    /// * `contract_address` - Tongo contract address (hex string)
    /// * `passphrase` - Optional BIP-39 passphrase
    ///
    /// # Returns
    /// New WasmAccount instance or error
    #[wasm_bindgen(js_name = "fromMnemonic")]
    pub fn from_mnemonic(
        mnemonic: &str,
        address_index: u32,
        account_index: u32,
        contract_address: &str,
        passphrase: Option<String>,
    ) -> Result<WasmAccount, JsValue> {
        let contract_felt = parse_felt(contract_address)?;
        let passphrase_ref = passphrase.as_deref();

        let inner = from_sdk_result(krusty_kms_sdk::TongoAccount::from_mnemonic(
            mnemonic,
            address_index,
            account_index,
            contract_felt,
            passphrase_ref,
        ))
        .map_err(JsValue::from)?;

        Ok(Self { inner })
    }

    /// Create a new account from a private key.
    /// # Arguments
    /// * `private_key` - Private key as hex string (0x-prefixed)
    /// * `contract_address` - Tongo contract address (hex string)
    #[wasm_bindgen(js_name = "fromPrivateKey")]
    pub fn from_private_key(
        private_key: &str,
        contract_address: &str,
    ) -> Result<WasmAccount, JsValue> {
        let sk = parse_felt(private_key)?;
        let contract_felt = parse_felt(contract_address)?;

        let inner = from_sdk_result(krusty_kms_sdk::TongoAccount::from_private_key(
            sk,
            contract_felt,
        ))
        .map_err(JsValue::from)?;

        Ok(Self { inner })
    }

    /// Get the owner (spending) public key as hex string.
    #[wasm_bindgen(js_name = "ownerPublicKeyHex")]
    pub fn owner_public_key_hex(&self) -> Result<String, JsValue> {
        from_sdk_result(self.inner.owner_public_key_hex()).map_err(JsValue::from)
    }

    /// Get the contract address as hex string.
    #[wasm_bindgen(js_name = "contractAddress")]
    pub fn contract_address(&self) -> String {
        format!("{:#x}", self.inner.contract_address())
    }

    /// Get current account state.
    #[wasm_bindgen(js_name = "getState")]
    pub fn get_state(&self) -> WasmAccountState {
        WasmAccountState::from(self.inner.state().clone())
    }

    /// Update account state from on-chain data.
    #[wasm_bindgen(js_name = "updateState")]
    pub fn update_state(&mut self, state: WasmAccountState) -> Result<(), JsValue> {
        self.inner
            .update_state(state.try_into().map_err(JsValue::from)?);
        Ok(())
    }

    /// Check if account has sufficient balance for an operation.
    #[wasm_bindgen(js_name = "hasSufficientBalance")]
    pub fn has_sufficient_balance(&self, amount: &str) -> Result<bool, JsValue> {
        let amount = parse_u128_decimal(amount).map_err(JsValue::from)?;
        Ok(self.inner.has_sufficient_balance(amount))
    }

    /// Get total balance (available + pending).
    #[wasm_bindgen(js_name = "totalBalance")]
    pub fn total_balance(&self) -> Result<String, JsValue> {
        from_sdk_result(self.inner.total_balance())
            .map(|value| value.to_string())
            .map_err(JsValue::from)
    }

    /// Decrypt an ElGamal ciphertext using the account key.
    ///
    /// Returns the decrypted point as `g^m`. The caller must perform discrete
    /// log recovery to obtain the actual value `m`.
    ///
    /// # Arguments
    /// * `ciphertext` - The ciphertext to decrypt
    ///
    /// # Returns
    /// The decrypted point, including the identity point when the balance is zero
    #[wasm_bindgen(js_name = "decryptToPoint")]
    pub fn decrypt_to_point(
        &self,
        ciphertext: &WasmCiphertext,
    ) -> Result<WasmDecryptedPoint, JsValue> {
        let cipher = parse_ciphertext(ciphertext)?;
        let decrypted_point =
            from_sdk_result(self.inner.decrypt(&cipher)).map_err(JsValue::from)?;

        Ok(decrypted_point_to_wasm(decrypted_point))
    }

    /// Decrypt an ElGamal ciphertext and recover the balance value.
    ///
    /// This performs full decryption including discrete log recovery using
    /// brute force search. For large balances, this may be slow.
    ///
    /// # Arguments
    /// * `ciphertext` - The ciphertext to decrypt
    /// * `max_search` - Maximum value to search for (default: 1,000,000)
    ///
    /// # Returns
    /// The decrypted balance as a string (for large number support in JS)
    #[wasm_bindgen(js_name = "decryptBalance")]
    pub fn decrypt_balance(
        &self,
        ciphertext: &WasmCiphertext,
        max_search: Option<u64>,
    ) -> Result<String, JsValue> {
        let cipher = parse_ciphertext(ciphertext)?;

        let decrypted_point =
            from_sdk_result(self.inner.decrypt(&cipher)).map_err(JsValue::from)?;
        let max = max_search.unwrap_or(1_000_000);
        let balance =
            krusty_kms_crypto::recover_small_discrete_log(&decrypted_point, u128::from(max))
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(balance.to_string())
    }
}
