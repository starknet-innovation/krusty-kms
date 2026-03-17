//! WASM bindings for TONGO account management.
//!
//! Provides account creation, key derivation, and state management
//! functionality accessible from JavaScript/TypeScript.

use crate::error::{from_sdk_result, WasmError, WasmResult};
use crate::types::{WasmAccountState, WasmCiphertext, WasmKeypair, WasmNostrKeypair, WasmPoint};
use starknet_types_core::felt::Felt;
use wasm_bindgen::prelude::*;

/// WASM-accessible TONGO account.
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
    /// * `contract_address` - TONGO contract address (hex string)
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
    /// * `contract_address` - TONGO contract address (hex string)
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

    /// Get the private key as hex string.
    ///
    /// WARNING: Handle with extreme care. Never log or transmit.
    #[wasm_bindgen(js_name = "privateKeyHex")]
    pub fn private_key_hex(&self) -> String {
        self.inner.private_key_hex()
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
    pub fn update_state(&mut self, state: WasmAccountState) {
        self.inner.update_state(state.into());
    }

    /// Check if account has sufficient balance for an operation.
    #[wasm_bindgen(js_name = "hasSufficientBalance")]
    pub fn has_sufficient_balance(&self, amount: &str) -> bool {
        let amount: u128 = amount.parse().unwrap_or(u128::MAX);
        self.inner.has_sufficient_balance(amount)
    }

    /// Get total balance (available + pending).
    #[wasm_bindgen(js_name = "totalBalance")]
    pub fn total_balance(&self) -> String {
        self.inner.total_balance().to_string()
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
    /// The decrypted point g^m as (x, y) coordinates
    #[wasm_bindgen(js_name = "decryptToPoint")]
    pub fn decrypt_to_point(&self, ciphertext: &WasmCiphertext) -> Result<WasmPoint, JsValue> {
        // Parse ciphertext points
        let l_x = parse_felt(&ciphertext.l_x)?;
        let l_y = parse_felt(&ciphertext.l_y)?;
        let r_x = parse_felt(&ciphertext.r_x)?;
        let r_y = parse_felt(&ciphertext.r_y)?;

        let l = starknet_types_core::curve::ProjectivePoint::from_affine(l_x, l_y)
            .map_err(|e| JsValue::from_str(&format!("Invalid L point: {e:?}")))?;
        let r = starknet_types_core::curve::ProjectivePoint::from_affine(r_x, r_y)
            .map_err(|e| JsValue::from_str(&format!("Invalid R point: {e:?}")))?;

        let cipher = krusty_kms_common::ElGamalCiphertext { l, r };

        // Decrypt to get g^m
        let decrypted_point =
            from_sdk_result(self.inner.decrypt(&cipher)).map_err(JsValue::from)?;

        let affine = decrypted_point
            .to_affine()
            .map_err(|_| JsValue::from_str("Decrypted point is at infinity (balance = 0)"))?;

        Ok(WasmPoint {
            x: format!("{:#x}", affine.x()),
            y: format!("{:#x}", affine.y()),
        })
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
        // Parse ciphertext points
        let l_x = parse_felt(&ciphertext.l_x)?;
        let l_y = parse_felt(&ciphertext.l_y)?;
        let r_x = parse_felt(&ciphertext.r_x)?;
        let r_y = parse_felt(&ciphertext.r_y)?;

        let l = starknet_types_core::curve::ProjectivePoint::from_affine(l_x, l_y)
            .map_err(|e| JsValue::from_str(&format!("Invalid L point: {e:?}")))?;
        let r = starknet_types_core::curve::ProjectivePoint::from_affine(r_x, r_y)
            .map_err(|e| JsValue::from_str(&format!("Invalid R point: {e:?}")))?;

        let cipher = krusty_kms_common::ElGamalCiphertext { l, r };

        // Decrypt to get g^m
        let decrypted_point =
            from_sdk_result(self.inner.decrypt(&cipher)).map_err(JsValue::from)?;

        // Try to convert to affine - if it fails, it's the identity (balance = 0)
        if decrypted_point.to_affine().is_err() {
            return Ok("0".to_string());
        }

        // Perform discrete log recovery using brute force
        let max = max_search.unwrap_or(1_000_000);
        let balance =
            discrete_log_brute_force(&decrypted_point, max).map_err(|e| JsValue::from_str(&e))?;

        Ok(balance.to_string())
    }
}

/// Recover the discrete log m from g^m using brute force search.
///
/// This works for values up to `max_search`.
fn discrete_log_brute_force(
    g_m: &starknet_types_core::curve::ProjectivePoint,
    max_search: u64,
) -> Result<u128, String> {
    let generator = krusty_kms_crypto::StarkCurve::generator();

    // Try to convert to affine - if it fails, it's the identity (balance = 0)
    let target_affine = match g_m.to_affine() {
        Ok(a) => a,
        Err(_) => return Ok(0),
    };

    let mut current = generator.clone();

    for i in 1..=max_search {
        if let Ok(curr_affine) = current.to_affine() {
            if curr_affine.x() == target_affine.x() && curr_affine.y() == target_affine.y() {
                return Ok(i as u128);
            }
        }
        current = &current + &generator;
    }

    Err(format!(
        "Failed to recover balance (discrete log not found within search limit of {})",
        max_search
    ))
}

// Internal helper functions

/// Parse a hex string to Felt.
fn parse_felt(hex: &str) -> WasmResult<Felt> {
    Felt::from_hex(hex).map_err(|e| WasmError::SerializationError(e.to_string()))
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
        private_key: format!("{:#x}", kp.private_key),
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
        private_key: format!("{:#x}", kp.private_key),
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

/// Get the TONGO coin type constant (5454).
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

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    const TEST_MNEMONIC: &str =
        "habit hope tip crystal because grunt nation idea electric witness alert like";

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

        let new_state = WasmAccountState::new("1000".to_string(), "500".to_string(), 5);
        account.update_state(new_state);

        let state = account.get_state();
        assert_eq!(state.balance, "1000");
        assert_eq!(state.pending_balance, "500");
        assert_eq!(state.nonce, 5);
        assert_eq!(state.total_balance(), "1500");
    }

    #[wasm_bindgen_test]
    fn test_derive_starknet_keypair() {
        let kp = derive_starknet_keypair(TEST_MNEMONIC, 0, 0, None);
        assert!(kp.is_ok());

        let keypair = kp.unwrap();
        assert!(keypair.private_key.starts_with("0x"));
        assert!(keypair.public_key_x.starts_with("0x"));

        // Starknet keypair should be different from TONGO keypair (different coin types)
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

        // Nostr keypair should be different from both Starknet and TONGO keypairs
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
}
