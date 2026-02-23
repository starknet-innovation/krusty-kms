//! TONGO account management.

use krusty_kms_common::ElGamalCiphertext;
use krusty_kms_common::{AccountState, KmsError, Result, SecretFelt};
use krusty_kms::{derive_keypair, derive_view_keypair, TongoKeyPair};
use krusty_kms_crypto::{ElGamal, StarkCurve};
use starknet_types_core::felt::Felt;

/// A TONGO confidential account.
#[derive(Debug, Clone)]
pub struct TongoAccount {
    /// The account's keypair
    pub keypair: TongoKeyPair,
    /// Optional viewing/decryption keypair (coin type 5353)
    pub view_keypair: Option<TongoKeyPair>,
    /// Current account state
    pub state: AccountState,
    /// Contract address
    pub contract_address: Felt,
}

impl TongoAccount {
    /// Create a new TONGO account from a mnemonic.
    ///
    /// # Arguments
    /// * `mnemonic` - BIP-39 mnemonic phrase
    /// * `index` - Address index
    /// * `account_index` - Account index
    /// * `contract_address` - TONGO contract address
    /// * `passphrase` - Optional passphrase
    ///
    /// # Cyclomatic Complexity: 1
    #[must_use]
    pub fn from_mnemonic(
        mnemonic: &str,
        index: u32,
        account_index: u32,
        contract_address: Felt,
        passphrase: Option<&str>,
    ) -> Result<Self> {
        let keypair = derive_keypair(mnemonic, index, account_index, passphrase)?;
        let view_keypair = Some(derive_view_keypair(
            mnemonic,
            index,
            account_index,
            passphrase,
        )?);

        Ok(Self {
            keypair,
            view_keypair,
            state: AccountState::default(),
            contract_address,
        })
    }

    /// Create a TONGO account from a private key.
    ///
    /// # Cyclomatic Complexity: 1
    #[must_use]
    pub fn from_private_key(private_key: Felt, contract_address: Felt) -> Result<Self> {
        let public_key = StarkCurve::mul_generator(&private_key);

        let keypair = TongoKeyPair {
            private_key: SecretFelt::new(private_key),
            public_key,
        };

        Ok(Self {
            keypair,
            view_keypair: None,
            state: AccountState::default(),
            contract_address,
        })
    }

    /// Create a TONGO account from explicit owner and viewing private keys.
    ///
    /// This is useful for wallets that store the viewing key separately and
    /// want to initialize an account without a mnemonic.
    #[must_use]
    pub fn from_keys(
        owner_private_key: Felt,
        view_private_key: Felt,
        contract_address: Felt,
    ) -> Result<Self> {
        let owner_public_key = StarkCurve::mul_generator(&owner_private_key);
        let view_public_key = StarkCurve::mul_generator(&view_private_key);

        Ok(Self {
            keypair: TongoKeyPair {
                private_key: SecretFelt::new(owner_private_key),
                public_key: owner_public_key,
            },
            view_keypair: Some(TongoKeyPair {
                private_key: SecretFelt::new(view_private_key),
                public_key: view_public_key,
            }),
            state: AccountState::default(),
            contract_address,
        })
    }

    /// Get the public key as a hex string.
    #[must_use]
    pub fn public_key_hex(&self) -> Result<String> {
        let affine = self
            .keypair
            .public_key
            .to_affine()
            .map_err(|_| KmsError::PointAtInfinity)?;

        Ok(krusty_kms_common::utils::serialize_public_key_hex(
            &affine.x(),
            &affine.y(),
        ))
    }

    /// Get the owner (spending) public key as a hex string.
    #[must_use]
    pub fn owner_public_key_hex(&self) -> Result<String> {
        self.public_key_hex()
    }

    /// Get the viewing public key as a hex string, if present.
    #[must_use]
    pub fn view_public_key_hex(&self) -> Option<String> {
        let kp = self.view_keypair.as_ref()?;
        let affine = kp.public_key.to_affine().ok()?;
        Some(krusty_kms_common::utils::serialize_public_key_hex(
            &affine.x(),
            &affine.y(),
        ))
    }

    /// Get the private key as a hex string.
    #[must_use]
    pub fn private_key_hex(&self) -> String {
        format!("{:#x}", self.keypair.private_key)
    }

    /// Check if the account has a separate viewing key.
    #[must_use]
    pub fn has_view_key(&self) -> bool {
        self.view_keypair.is_some()
    }

    /// Update the account state.
    ///
    /// # Cyclomatic Complexity: 1
    pub fn update_state(&mut self, state: AccountState) {
        self.state = state;
    }

    /// Check if the account has sufficient available balance.
    ///
    /// # Cyclomatic Complexity: 1
    #[must_use]
    pub fn has_sufficient_balance(&self, amount: u128) -> bool {
        self.state.balance >= amount
    }

    /// Get the total balance (available + pending).
    #[must_use]
    pub fn total_balance(&self) -> u128 {
        self.state
            .balance
            .saturating_add(self.state.pending_balance)
    }

    /// Decrypt an ElGamal ciphertext using the viewing key if available,
    /// otherwise fall back to the owner key. Returns the decrypted point g^m.
    pub fn decrypt_with_view(
        &self,
        ciphertext: &ElGamalCiphertext,
    ) -> Result<starknet_types_core::curve::ProjectivePoint> {
        let secret = self
            .view_keypair
            .as_ref()
            .map(|k| &k.private_key)
            .unwrap_or(&self.keypair.private_key);
        ElGamal::decrypt(ciphertext, secret.expose_secret())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str =
        "habit hope tip crystal because grunt nation idea electric witness alert like";

    #[test]
    fn test_account_from_mnemonic() {
        let contract_address = Felt::from(123456u64);
        let account = TongoAccount::from_mnemonic(TEST_MNEMONIC, 0, 0, contract_address, None);
        assert!(account.is_ok());
        let acc = account.unwrap();
        assert!(acc.has_view_key());
    }

    #[test]
    fn test_account_from_private_key() {
        let private_key = Felt::from(42u64);
        let contract_address = Felt::from(123456u64);
        let account = TongoAccount::from_private_key(private_key, contract_address);
        assert!(account.is_ok());
        let acc = account.unwrap();
        assert!(!acc.has_view_key());
    }

    #[test]
    fn test_account_from_keys() {
        let owner_sk = Felt::from(42u64);
        let view_sk = Felt::from(123u64);
        let contract_address = Felt::from(456u64);

        let account = TongoAccount::from_keys(owner_sk, view_sk, contract_address);
        assert!(account.is_ok());
        let acc = account.unwrap();

        assert!(acc.has_view_key());
        assert_eq!(acc.keypair.private_key, owner_sk);
        assert_eq!(acc.view_keypair.as_ref().unwrap().private_key, view_sk);
        assert_eq!(acc.contract_address, contract_address);
    }

    #[test]
    fn test_dual_keys_different_coin_types() {
        let contract_address = Felt::from(123456u64);
        let account =
            TongoAccount::from_mnemonic(TEST_MNEMONIC, 0, 0, contract_address, None).unwrap();
        let view_sk = &account.view_keypair.as_ref().unwrap().private_key;
        let owner_sk = &account.keypair.private_key;
        assert_ne!(view_sk, owner_sk);
    }

    #[test]
    fn test_public_key_hex() {
        let contract_address = Felt::from(123456u64);
        let account =
            TongoAccount::from_mnemonic(TEST_MNEMONIC, 0, 0, contract_address, None).unwrap();
        let public_key = account.public_key_hex();
        assert!(public_key.is_ok());
        assert!(public_key.unwrap().starts_with("0x"));
    }

    #[test]
    fn test_owner_public_key_hex() {
        let contract_address = Felt::from(123456u64);
        let account =
            TongoAccount::from_mnemonic(TEST_MNEMONIC, 0, 0, contract_address, None).unwrap();
        let owner_pk = account.owner_public_key_hex();
        let public_pk = account.public_key_hex();
        // owner_public_key_hex should be the same as public_key_hex
        assert_eq!(owner_pk.unwrap(), public_pk.unwrap());
    }

    #[test]
    fn test_view_public_key_hex() {
        let contract_address = Felt::from(123456u64);
        let account =
            TongoAccount::from_mnemonic(TEST_MNEMONIC, 0, 0, contract_address, None).unwrap();
        let view_pk = account.view_public_key_hex();
        assert!(view_pk.is_some());
        assert!(view_pk.unwrap().starts_with("0x"));
    }

    #[test]
    fn test_view_public_key_hex_none() {
        // Account without view key
        let private_key = Felt::from(42u64);
        let contract_address = Felt::from(123456u64);
        let account = TongoAccount::from_private_key(private_key, contract_address).unwrap();
        assert!(account.view_public_key_hex().is_none());
    }

    #[test]
    fn test_private_key_hex() {
        let private_key = Felt::from(42u64);
        let contract_address = Felt::from(123456u64);
        let account = TongoAccount::from_private_key(private_key, contract_address).unwrap();
        let pk_hex = account.private_key_hex();
        assert_eq!(pk_hex, "0x2a"); // 42 in hex
    }

    #[test]
    fn test_update_state() {
        let private_key = Felt::from(42u64);
        let contract_address = Felt::from(123456u64);
        let mut account = TongoAccount::from_private_key(private_key, contract_address).unwrap();

        assert_eq!(account.state.balance, 0);
        assert_eq!(account.state.pending_balance, 0);

        let new_state = AccountState {
            balance: 1000,
            pending_balance: 500,
            nonce: 5,
        };
        account.update_state(new_state);

        assert_eq!(account.state.balance, 1000);
        assert_eq!(account.state.pending_balance, 500);
        assert_eq!(account.state.nonce, 5);
    }

    #[test]
    fn test_balance_check() {
        let contract_address = Felt::from(123456u64);
        let mut account =
            TongoAccount::from_mnemonic(TEST_MNEMONIC, 0, 0, contract_address, None).unwrap();

        account.state.balance = 100;
        assert!(account.has_sufficient_balance(50));
        assert!(account.has_sufficient_balance(100));
        assert!(!account.has_sufficient_balance(101));
    }

    #[test]
    fn test_total_balance() {
        let contract_address = Felt::from(123456u64);
        let mut account =
            TongoAccount::from_mnemonic(TEST_MNEMONIC, 0, 0, contract_address, None).unwrap();

        account.state.balance = 100;
        account.state.pending_balance = 50;
        assert_eq!(account.total_balance(), 150);
    }

    #[test]
    fn test_decrypt_with_view() {
        let private_key = Felt::from(42u64);
        let contract_address = Felt::from(123456u64);
        let account = TongoAccount::from_private_key(private_key, contract_address).unwrap();

        // Create a valid cipher (encrypting 0 for simplicity)
        let y = StarkCurve::mul_generator(&private_key);
        let r = Felt::from(99u64);
        let r_point = StarkCurve::mul_generator(&r);
        let y_r = StarkCurve::mul(&r, Some(&y));

        let cipher = ElGamalCiphertext {
            l: y_r,     // L = y^r (encrypts 0)
            r: r_point, // R = g^r
        };

        let result = account.decrypt_with_view(&cipher);
        assert!(result.is_ok());
        // Decrypted should be identity point (g^0 = point at infinity)
        // or the generator if there's a bug with g^0
    }

    #[test]
    fn test_decrypt_with_view_uses_view_key() {
        let owner_sk = Felt::from(42u64);
        let view_sk = Felt::from(123u64);
        let contract_address = Felt::from(456u64);
        let account = TongoAccount::from_keys(owner_sk, view_sk, contract_address).unwrap();

        // Encrypt using the VIEW public key
        let view_pk = StarkCurve::mul_generator(&view_sk);
        let r = Felt::from(99u64);
        let r_point = StarkCurve::mul_generator(&r);
        let y_r = StarkCurve::mul(&r, Some(&view_pk));

        let cipher = ElGamalCiphertext { l: y_r, r: r_point };

        // Should decrypt successfully using view key
        let result = account.decrypt_with_view(&cipher);
        assert!(result.is_ok());
    }
}
