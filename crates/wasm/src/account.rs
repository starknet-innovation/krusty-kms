//! WASM bindings for Tongo account management.
//!
//! Provides account creation, key derivation, and state management
//! functionality accessible from JavaScript/TypeScript.

use crate::error::{from_sdk_result, WasmError, WasmResult};
use crate::types::{
    WasmAccountState, WasmCiphertext, WasmDecryptedPoint, WasmKeypair, WasmNostrKeypair,
};
use krusty_kms::AccountClass;
use starknet_types_core::felt::Felt;
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

// Internal helper functions

/// Parse a hex string to Felt.
fn parse_felt(hex: &str) -> WasmResult<Felt> {
    Felt::from_hex(hex).map_err(|e| WasmError::SerializationError(e.to_string()))
}

fn parse_u128_decimal(value: &str) -> WasmResult<u128> {
    value
        .parse()
        .map_err(|_| WasmError::SerializationError("invalid decimal amount".to_string()))
}

fn parse_ciphertext(
    ciphertext: &WasmCiphertext,
) -> Result<krusty_kms_common::ElGamalCiphertext, JsValue> {
    let l_x = parse_felt(&ciphertext.l_x)?;
    let l_y = parse_felt(&ciphertext.l_y)?;
    let r_x = parse_felt(&ciphertext.r_x)?;
    let r_y = parse_felt(&ciphertext.r_y)?;

    let l = starknet_types_core::curve::ProjectivePoint::from_affine(l_x, l_y)
        .map_err(|e| JsValue::from_str(&format!("Invalid L point: {e:?}")))?;
    let r = starknet_types_core::curve::ProjectivePoint::from_affine(r_x, r_y)
        .map_err(|e| JsValue::from_str(&format!("Invalid R point: {e:?}")))?;

    Ok(krusty_kms_common::ElGamalCiphertext { l, r })
}

fn decrypted_point_to_wasm(
    point: starknet_types_core::curve::ProjectivePoint,
) -> WasmDecryptedPoint {
    match point.to_affine() {
        Ok(affine) => WasmDecryptedPoint {
            is_identity: false,
            x: Some(format!("{:#x}", affine.x())),
            y: Some(format!("{:#x}", affine.y())),
        },
        Err(_) => WasmDecryptedPoint {
            is_identity: true,
            x: None,
            y: None,
        },
    }
}

/// Generate a new random mnemonic phrase.
#[wasm_bindgen(js_name = "generateMnemonic")]
pub fn generate_mnemonic(word_count: Option<u8>) -> Result<String, JsValue> {
    let count = word_count.unwrap_or(12) as usize;
    from_sdk_result(krusty_kms::generate_mnemonic(count)).map_err(JsValue::from)
}

/// Validate a mnemonic phrase.
#[wasm_bindgen(js_name = "validateMnemonic")]
pub fn validate_mnemonic(mnemonic: &str) -> bool {
    krusty_kms::validate_mnemonic(mnemonic).is_ok()
}

/// Derive a keypair from mnemonic (for external use).
#[wasm_bindgen(js_name = "deriveKeypair")]
pub fn derive_keypair(
    mnemonic: &str,
    address_index: u32,
    account_index: u32,
    passphrase: Option<String>,
) -> Result<WasmKeypair, JsValue> {
    let kp = from_sdk_result(krusty_kms::derive_keypair(
        mnemonic,
        address_index,
        account_index,
        passphrase.as_deref(),
    ))
    .map_err(JsValue::from)?;

    let affine = kp
        .public_key
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid public key point"))?;

    Ok(WasmKeypair {
        private_key: kp.private_key.expose_secret_hex(),
        public_key_x: format!("{:#x}", affine.x()),
        public_key_y: format!("{:#x}", affine.y()),
    })
}

/// Derive a Starknet account keypair from mnemonic (coin type 9004).
///
/// This is used for signing Starknet transactions and deriving the
/// OpenZeppelin account contract address.
///
/// # Arguments
/// * `mnemonic` - 12 or 24 word BIP-39 mnemonic
/// * `address_index` - HD wallet address index (default: 0)
/// * `account_index` - HD wallet account index (default: 0)
/// * `passphrase` - Optional BIP-39 passphrase
///
/// # Returns
/// Keypair with private key and public key coordinates
#[wasm_bindgen(js_name = "deriveStarknetKeypair")]
pub fn derive_starknet_keypair(
    mnemonic: &str,
    address_index: u32,
    account_index: u32,
    passphrase: Option<String>,
) -> Result<WasmKeypair, JsValue> {
    let kp = from_sdk_result(krusty_kms::derive_keypair_with_coin_type(
        mnemonic,
        address_index,
        account_index,
        krusty_kms::STARKNET_COIN_TYPE,
        passphrase.as_deref(),
    ))
    .map_err(JsValue::from)?;

    let affine = kp
        .public_key
        .to_affine()
        .map_err(|_| JsValue::from_str("Invalid public key point"))?;

    Ok(WasmKeypair {
        private_key: kp.private_key.expose_secret_hex(),
        public_key_x: format!("{:#x}", affine.x()),
        public_key_y: format!("{:#x}", affine.y()),
    })
}

/// Derive an OpenZeppelin account contract address from a public key.
///
/// This calculates the counterfactual address for an OpenZeppelin account
/// using the standard contract address derivation formula.
///
/// # Arguments
/// * `public_key_x` - The x-coordinate of the Stark public key (hex string)
/// * `class_hash` - The OpenZeppelin account class hash (hex string)
/// * `salt` - Optional salt for address derivation (hex string, defaults to "0x0")
///
/// # Returns
/// The derived account contract address as hex string
#[wasm_bindgen(js_name = "deriveOzAccountAddress")]
pub fn derive_oz_account_address(
    public_key_x: &str,
    class_hash: &str,
    salt: Option<String>,
) -> Result<String, JsValue> {
    let public_key = parse_felt(public_key_x)?;
    let class_hash_felt = parse_felt(class_hash)?;
    let salt_felt = match salt {
        Some(s) => Some(parse_felt(&s)?),
        None => None,
    };

    let address = from_sdk_result(krusty_kms::derive_oz_account_address(
        &public_key,
        &class_hash_felt,
        salt_felt.as_ref(),
    ))
    .map_err(JsValue::from)?;

    Ok(format!("{:#x}", address))
}

/// Get the Starknet coin type constant (9004).
#[wasm_bindgen(js_name = "getStarknetCoinType")]
pub fn get_starknet_coin_type() -> u32 {
    krusty_kms::STARKNET_COIN_TYPE
}

/// Get the Tongo coin type constant (5454).
#[wasm_bindgen(js_name = "getTongoCoinType")]
pub fn get_tongo_coin_type() -> u32 {
    krusty_kms::TONGO_COIN_TYPE
}

/// Get the Nostr coin type constant (1237).
#[wasm_bindgen(js_name = "getNostrCoinType")]
pub fn get_nostr_coin_type() -> u32 {
    krusty_kms::NOSTR_COIN_TYPE
}

/// Derive a Nostr keypair from mnemonic (coin type 1237).
///
/// Uses secp256k1 curve (not Stark curve). The public key is x-only
/// (32 bytes) as per BIP-340/Nostr convention.
///
/// Derivation path: m/44'/1237'/{account_index}'/0/{address_index}
///
/// # Arguments
/// * `mnemonic` - 12 or 24 word BIP-39 mnemonic
/// * `address_index` - HD wallet address index (default: 0)
/// * `account_index` - HD wallet account index (default: 0)
/// * `passphrase` - Optional BIP-39 passphrase
///
/// # Returns
/// Nostr keypair with private key and x-only public key (both 64 hex chars)
#[wasm_bindgen(js_name = "deriveNostrKeypair")]
pub fn derive_nostr_keypair(
    mnemonic: &str,
    address_index: u32,
    account_index: u32,
    passphrase: Option<String>,
) -> Result<WasmNostrKeypair, JsValue> {
    let kp = from_sdk_result(krusty_kms::derive_nostr_keypair(
        mnemonic,
        address_index,
        account_index,
        passphrase.as_deref(),
    ))
    .map_err(JsValue::from)?;

    // Convert to hex strings (no 0x prefix for Nostr compatibility)
    let private_key = hex::encode(kp.private_key);
    let public_key = hex::encode(kp.public_key);

    Ok(WasmNostrKeypair {
        private_key,
        public_key,
    })
}

/// Derive a Starknet keypair using old Argent's "double derivation" scheme.
///
/// Old Argent wallets use a two-step derivation:
/// 1. Derive ETH private key at `m/44'/60'/0'/0/0` (raw, no grindKey)
/// 2. Use ETH key as BIP-32 seed, derive `m/44'/9004'/0'/0/{index}`, then grindKey
///
/// This is needed to recover keys for accounts created with old Argent-X.
/// Braavos and new Argent use direct `m/44'/9004'/0'/0/{index}` derivation instead.
///
/// # Arguments
/// * `mnemonic` - 12 or 24 word BIP-39 mnemonic
/// * `address_index` - HD wallet address index (default: 0)
/// * `account_index` - HD wallet account index (default: 0)
#[wasm_bindgen(js_name = "deriveArgentLegacyKeypair")]
pub fn derive_argent_legacy_keypair(
    mnemonic: &str,
    address_index: u32,
    account_index: u32,
) -> Result<WasmKeypair, JsValue> {
    let pk = krusty_kms::derive_argent_legacy_private_key(mnemonic, address_index, account_index)
        .map_err(|e| JsValue::from_str(&format!("Argent legacy derivation failed: {e}")))?;
    let pubk = krusty_kms::stark_public_key(&pk);

    Ok(WasmKeypair {
        private_key: format!("{:#066x}", pk),
        public_key_x: format!("{:#x}", pubk),
        public_key_y: String::new(), // x-coordinate only for Stark keys
    })
}

/// Derive an Argent account contract address from a public key.
///
/// Uses the standard Argent constructor calldata format `(0, public_key, 0)`.
///
/// # Arguments
/// * `public_key` - The Stark public key (hex string)
/// * `class_hash` - Optional custom class hash (hex string). Defaults to the
///   standard Argent v0.4.0 class hash.
///
/// # Returns
/// The derived account contract address as hex string
#[wasm_bindgen(js_name = "deriveArgentAccountAddress")]
pub fn derive_argent_account_address(
    public_key: &str,
    class_hash: Option<String>,
) -> Result<String, JsValue> {
    let pk = parse_felt(public_key)?;
    let account = match class_hash {
        Some(ref hash) => {
            let ch = parse_felt(hash)?;
            krusty_kms::ArgentAccount::with_class_hash(ch)
        }
        None => krusty_kms::ArgentAccount::new(),
    };
    let address = account
        .calculate_address(&pk, krusty_kms::SaltPolicy::PublicKey)
        .map_err(|e| JsValue::from_str(&format!("Failed to derive Argent address: {e}")))?;
    Ok(format!("{:#x}", address))
}

/// Derive a Braavos account contract address from a public key.
///
/// Uses the standard Braavos constructor calldata format `(public_key)`.
///
/// # Arguments
/// * `public_key` - The Stark public key (hex string)
/// * `class_hash` - Optional custom class hash (hex string). Defaults to the
///   standard Braavos v1.0.0 class hash.
///
/// # Returns
/// The derived account contract address as hex string
#[wasm_bindgen(js_name = "deriveBraavosAccountAddress")]
pub fn derive_braavos_account_address(
    public_key: &str,
    class_hash: Option<String>,
) -> Result<String, JsValue> {
    let pk = parse_felt(public_key)?;
    let account = match class_hash {
        Some(ref hash) => {
            let ch = parse_felt(hash)?;
            krusty_kms::BraavosAccount::with_class_hash(ch)
        }
        None => krusty_kms::BraavosAccount::new(),
    };
    let address = account
        .calculate_address(&pk, krusty_kms::SaltPolicy::PublicKey)
        .map_err(|e| JsValue::from_str(&format!("Failed to derive Braavos address: {e}")))?;
    Ok(format!("{:#x}", address))
}

/// Calculate a Starknet contract address from deployment parameters.
///
/// Implements the standard contract address derivation formula using
/// `computeHashOnElements`.
///
/// # Arguments
/// * `salt` - Salt value (hex string)
/// * `class_hash` - Contract class hash (hex string)
/// * `constructor_calldata` - Array of hex strings for constructor calldata
/// * `deployer_address` - Deployer address (hex string, typically "0x0")
///
/// # Returns
/// The calculated contract address as hex string
#[wasm_bindgen(js_name = "calculateContractAddress")]
pub fn calculate_contract_address(
    salt: &str,
    class_hash: &str,
    constructor_calldata: Vec<String>,
    deployer_address: &str,
) -> Result<String, JsValue> {
    let salt_felt = parse_felt(salt)?;
    let class_hash_felt = parse_felt(class_hash)?;
    let deployer_felt = parse_felt(deployer_address)?;
    let calldata: Vec<Felt> = constructor_calldata
        .iter()
        .map(|s| parse_felt(s))
        .collect::<Result<Vec<_>, _>>()?;

    let address = krusty_kms::calculate_contract_address(
        &salt_felt,
        &class_hash_felt,
        &calldata,
        &deployer_felt,
    )
    .map_err(|e| JsValue::from_str(&format!("Failed to calculate contract address: {e}")))?;

    Ok(format!("{:#x}", address))
}

/// Get known account class hashes for common Starknet account implementations.
///
/// Returns a JSON string containing class hashes organized by account type
/// and version, covering OpenZeppelin, Argent, and Braavos accounts.
///
/// # Returns
/// JSON string with nested object: `{ oz: { ... }, argent: { ... }, braavos: { ... } }`
#[wasm_bindgen(js_name = "getAccountClassHashes")]
pub fn get_account_class_hashes() -> String {
    let hashes = serde_json::json!({
        "oz": {
            "3.0.0": {
                "SN_MAIN": "0x01d1777db36cdd06dd62cfde77b1b6ae06412af95d57a13dc40ac77b8a702381",
                "SN_SEPOLIA": "0x01d1777db36cdd06dd62cfde77b1b6ae06412af95d57a13dc40ac77b8a702381"
            }
        },
        "argent": {
            "0.4.0": krusty_kms::ArgentAccount::CLASS_HASH,
            "0.3.1": "0x29927c8af6bccf3f6fda035981e765a7bdbf18a2dc0d630494f8758aa908e2b",
            "0.3.0": "0x1a736d6ed154502257f02b1ccdf4d9d1089f80811cd6acad48e6b6a9d1f2003"
        },
        "argent_legacy": {
            "proxy": "0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918",
            "0.2.3": "0x033434ad846cdd5f23eb73ff09fe6fddd568284a0fb7d1be20ee482f044dabe2",
            "0.2.2": "0x01a7820094feaf82d53f53f214b81292d717e7bb9a92bb2488092cd306f3993f",
            "0.2.1": "0x03e327de1c40540b98d05cbcb13552008e36f0ec8d61d46956d2f9752c294328",
            "0.2.0": "0x025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918"
        },
        "braavos": {
            "1.0.0": krusty_kms::BraavosAccount::CLASS_HASH,
            "legacy": krusty_kms::BraavosAccount::LEGACY_CLASS_HASH
        }
    });
    hashes.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    const TEST_MNEMONIC: &str =
        "habit hope tip crystal because grunt nation idea electric witness alert like";

    fn js_error_message(error: JsValue) -> String {
        error
            .as_string()
            .or_else(|| {
                js_sys::Reflect::get(&error, &JsValue::from_str("message"))
                    .ok()
                    .and_then(|value| value.as_string())
            })
            .unwrap_or_default()
    }

    #[wasm_bindgen_test]
    fn test_generate_mnemonic() {
        let mnemonic = generate_mnemonic(Some(12)).unwrap();
        assert!(validate_mnemonic(&mnemonic));
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }

    #[wasm_bindgen_test]
    fn test_account_from_mnemonic() {
        let contract = "0x1234";
        let account = WasmAccount::from_mnemonic(TEST_MNEMONIC, 0, 0, contract, None);
        assert!(account.is_ok());

        let acc = account.unwrap();
        assert!(acc.owner_public_key_hex().is_ok());
    }

    #[wasm_bindgen_test]
    fn test_account_from_private_key() {
        let contract = "0x1234";
        let private_key = "0x2a"; // 42 in hex
        let account = WasmAccount::from_private_key(private_key, contract);
        assert!(account.is_ok());
    }

    #[wasm_bindgen_test]
    fn test_derive_keypair() {
        let kp = derive_keypair(TEST_MNEMONIC, 0, 0, None);
        assert!(kp.is_ok());

        let keypair = kp.unwrap();
        assert!(keypair.private_key.starts_with("0x"));
        assert!(keypair.public_key_x.starts_with("0x"));
    }

    #[wasm_bindgen_test]
    fn test_state_management() {
        let contract = "0x1234";
        let mut account = WasmAccount::from_private_key("0x2a", contract).unwrap();

        let new_state = WasmAccountState::new("1000".to_string(), "500".to_string(), 5).unwrap();
        account.update_state(new_state).unwrap();

        let state = account.get_state();
        assert_eq!(state.balance, "1000");
        assert_eq!(state.pending_balance, "500");
        assert_eq!(state.nonce, 5);
        assert_eq!(state.total_balance().unwrap(), "1500");
    }

    #[wasm_bindgen_test]
    fn test_state_rejects_invalid_balance_strings() {
        let err = WasmAccountState::new("abc".to_string(), "500".to_string(), 5).unwrap_err();
        assert_eq!(
            js_error_message(err),
            "Serialization error: balance must be a valid unsigned decimal string"
        );
    }

    #[wasm_bindgen_test]
    fn test_total_balance_rejects_invalid_state_fields() {
        let state = WasmAccountState {
            balance: "oops".to_string(),
            pending_balance: "500".to_string(),
            nonce: 5,
        };

        let err = state.total_balance().unwrap_err();
        assert_eq!(
            js_error_message(err),
            "Serialization error: balance must be a valid unsigned decimal string"
        );
    }

    #[wasm_bindgen_test]
    fn test_account_total_balance_rejects_overflow() {
        let contract = "0x1234";
        let mut account = WasmAccount::from_private_key("0x2a", contract).unwrap();
        let overflow_state =
            WasmAccountState::new(u128::MAX.to_string(), "1".to_string(), 0).unwrap();
        account.update_state(overflow_state).unwrap();

        let err = account.total_balance().unwrap_err();
        assert_eq!(
            js_error_message(err),
            "Invalid amount: account total balance overflow"
        );
    }

    #[wasm_bindgen_test]
    fn test_update_state_rejects_invalid_pending_balance() {
        let contract = "0x1234";
        let mut account = WasmAccount::from_private_key("0x2a", contract).unwrap();
        let invalid_state = WasmAccountState {
            balance: "1000".to_string(),
            pending_balance: "oops".to_string(),
            nonce: 5,
        };

        let err = account.update_state(invalid_state).unwrap_err();
        assert_eq!(
            js_error_message(err),
            "Serialization error: pending_balance must be a valid unsigned decimal string"
        );
    }

    #[wasm_bindgen_test]
    fn test_has_sufficient_balance_rejects_invalid_amounts() {
        let account = WasmAccount::from_private_key("0x2a", "0x1234").unwrap();
        let error = account.has_sufficient_balance("not-a-number").unwrap_err();
        assert_eq!(
            js_error_message(error),
            "Serialization error: invalid decimal amount"
        );
    }

    #[wasm_bindgen_test]
    fn test_decrypt_to_point_represents_zero_balance_as_identity() {
        let account = WasmAccount::from_private_key("0x2a", "0x1234").unwrap();
        let public_key = account.inner.owner_public_key().clone();
        let encryption = krusty_kms_crypto::ElGamal::encrypt(
            &Felt::ZERO,
            &public_key,
            &Felt::from(999u64),
            &Felt::from(7u64),
        )
        .unwrap();
        let l = encryption.l.to_affine().unwrap();
        let r = encryption.r.to_affine().unwrap();

        let ciphertext = WasmCiphertext {
            l_x: format!("{:#x}", l.x()),
            l_y: format!("{:#x}", l.y()),
            r_x: format!("{:#x}", r.x()),
            r_y: format!("{:#x}", r.y()),
        };

        let decrypted = account.decrypt_to_point(&ciphertext).unwrap();
        assert!(decrypted.is_identity);
        assert!(decrypted.x.is_none());
        assert!(decrypted.y.is_none());
    }

    #[wasm_bindgen_test]
    fn test_derive_starknet_keypair() {
        let kp = derive_starknet_keypair(TEST_MNEMONIC, 0, 0, None);
        assert!(kp.is_ok());

        let keypair = kp.unwrap();
        assert!(keypair.private_key.starts_with("0x"));
        assert!(keypair.public_key_x.starts_with("0x"));

        // Starknet keypair should be different from Tongo keypair (different coin types)
        let tongo_kp = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        assert_ne!(keypair.private_key, tongo_kp.private_key);
    }

    #[wasm_bindgen_test]
    fn test_derive_oz_account_address() {
        // First derive a Starknet keypair
        let kp = derive_starknet_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();

        // Use the latest manifest-backed OZ class hash.
        let oz_class_hash = "0x01d1777db36cdd06dd62cfde77b1b6ae06412af95d57a13dc40ac77b8a702381";

        let address = derive_oz_account_address(&kp.public_key_x, oz_class_hash, None);
        assert!(address.is_ok());

        let addr = address.unwrap();
        assert!(addr.starts_with("0x"));
    }

    #[wasm_bindgen_test]
    fn test_coin_type_constants() {
        assert_eq!(get_starknet_coin_type(), 9004);
        assert_eq!(get_tongo_coin_type(), 5454);
        assert_eq!(get_nostr_coin_type(), 1237);
    }

    #[wasm_bindgen_test]
    fn test_derive_nostr_keypair() {
        let kp = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None);
        assert!(kp.is_ok());

        let keypair = kp.unwrap();
        // Nostr keys are 64 hex chars (32 bytes) without 0x prefix
        assert_eq!(keypair.private_key.len(), 64);
        assert_eq!(keypair.public_key.len(), 64);
        // Should be valid hex
        assert!(hex::decode(&keypair.private_key).is_ok());
        assert!(hex::decode(&keypair.public_key).is_ok());
    }

    #[wasm_bindgen_test]
    fn test_nostr_keypair_different_from_starknet() {
        let nostr_kp = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let starknet_kp = derive_starknet_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let tongo_kp = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();

        // Nostr keypair should be different from both Starknet and Tongo keypairs
        // (different curves and coin types)
        assert_ne!(
            nostr_kp.private_key,
            starknet_kp.private_key.trim_start_matches("0x")
        );
        assert_ne!(
            nostr_kp.private_key,
            tongo_kp.private_key.trim_start_matches("0x")
        );
    }

    #[wasm_bindgen_test]
    fn test_nostr_keypair_deterministic() {
        // Same mnemonic should produce same keypair
        let kp1 = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let kp2 = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        assert_eq!(kp1.private_key, kp2.private_key);
        assert_eq!(kp1.public_key, kp2.public_key);

        // Different index should produce different keypair
        let kp3 = derive_nostr_keypair(TEST_MNEMONIC, 1, 0, None).unwrap();
        assert_ne!(kp1.private_key, kp3.private_key);
    }

    // -------------------------------------------------------------------
    // Category G: Account class preset tests
    // -------------------------------------------------------------------

    #[wasm_bindgen_test]
    fn test_derive_argent_account_address() {
        let pk = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let addr = derive_argent_account_address(pk, None).unwrap();
        assert!(addr.starts_with("0x"));
        assert_ne!(addr, "0x0");
    }

    #[wasm_bindgen_test]
    fn test_derive_braavos_account_address() {
        let pk = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let addr = derive_braavos_account_address(pk, None).unwrap();
        assert!(addr.starts_with("0x"));
        assert_ne!(addr, "0x0");
    }

    #[wasm_bindgen_test]
    fn test_different_account_types_different_addresses() {
        let pk = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let argent_addr = derive_argent_account_address(pk, None).unwrap();
        let braavos_addr = derive_braavos_account_address(pk, None).unwrap();
        assert_ne!(argent_addr, braavos_addr);
    }

    #[wasm_bindgen_test]
    fn test_calculate_contract_address() {
        let salt = "0x1";
        let class_hash = "0xdeadbeef";
        let calldata = vec!["0x1".to_string(), "0x2".to_string()];
        let deployer = "0x0";
        let addr = calculate_contract_address(salt, class_hash, calldata, deployer).unwrap();
        assert!(addr.starts_with("0x"));
        assert_ne!(addr, "0x0");
    }

    #[wasm_bindgen_test]
    fn test_get_account_class_hashes() {
        let json_str = get_account_class_hashes();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed.get("argent").is_some());
        assert!(parsed.get("argent_legacy").is_some());
        assert!(parsed.get("braavos").is_some());
        assert!(parsed.get("oz").is_some());

        // Verify argent_legacy contains the expected Cairo 0 class hashes
        let legacy = parsed.get("argent_legacy").unwrap();
        assert!(legacy.get("proxy").is_some());
        assert!(legacy.get("0.2.3").is_some());
        assert!(legacy.get("0.2.2").is_some());
        assert!(legacy.get("0.2.1").is_some());
        assert!(legacy.get("0.2.0").is_some());
    }
}
