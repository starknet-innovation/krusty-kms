//! Types for interacting with Tongo contracts on Starknet.

use krusty_kms_common::{utils, ElGamalCiphertext, Result};
use krusty_kms_crypto::ElGamal;
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// Default discrete-log search limit retained for legacy helpers.
pub const DEFAULT_DECRYPT_SEARCH_LIMIT: u128 = 1_000_000;

/// Cipher balance stored on-chain (ElGamal ciphertext).
#[derive(Debug, Clone)]
pub struct CipherBalance {
    pub l: ProjectivePoint,
    pub r: ProjectivePoint,
}

/// Account state from the Tongo contract.
#[derive(Debug, Clone)]
pub struct AccountState {
    /// Current spendable balance (encrypted)
    pub balance: CipherBalance,
    /// Pending balance from transfers (encrypted)
    pub pending: CipherBalance,
    /// Account nonce
    pub nonce: Felt,
}

/// Decrypted account state.
#[derive(Debug, Clone)]
pub struct DecryptedAccountState {
    /// Current spendable balance (plaintext)
    pub balance: u128,
    /// Pending balance from transfers (plaintext)
    pub pending: u128,
    /// Account nonce
    pub nonce: Felt,
}

/// Decrypt a cipher balance using ElGamal decryption.
///
/// Given C = (L, R) = (g^m * y^r, g^r), where:
/// - g is the generator
/// - m is the message (balance)
/// - y is the public key
/// - r is the random nonce
///
/// We can decrypt by computing: m = L / R^x, where x is the private key.
///
/// # Cyclomatic Complexity: 3
pub fn decrypt_cipher_balance_with_limit(
    private_key: &Felt,
    cipher: &CipherBalance,
    max_balance: u128,
) -> Result<u128> {
    let ciphertext = ElGamalCiphertext {
        l: cipher.l.clone(),
        r: cipher.r.clone(),
    };
    ElGamal::decrypt_balance_with_limit(&ciphertext, private_key, max_balance)
}

/// Decrypt a cipher balance using a conservative default search bound.
#[deprecated(
    since = "0.3.0",
    note = "Use decrypt_cipher_balance_with_limit to make the discrete-log search bound explicit"
)]
pub fn decrypt_cipher_balance_with_default_limit(
    private_key: &Felt,
    cipher: &CipherBalance,
) -> Result<u128> {
    decrypt_cipher_balance_with_limit(private_key, cipher, DEFAULT_DECRYPT_SEARCH_LIMIT)
}

/// Convert ERC-20 amount to Tongo units (ceiling division by rate).
pub fn erc20_to_tongo(erc20_amount: u128, rate: u128) -> Result<u128> {
    utils::base_units_to_tongo(erc20_amount, rate)
}

/// Convert Tongo amount to ERC-20 units.
pub fn tongo_to_erc20(tongo_amount: u128, rate: u128) -> Result<u128> {
    utils::tongo_to_base_units(tongo_amount, rate)
}

/// Authenticated encryption balance (raw on-chain representation).
#[derive(Debug, Clone)]
pub struct AEBalance {
    pub ciphertext: [u8; 64],
    pub nonce: [u8; 24],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_zero_balance() {
        // Create a cipher balance for 0: (y^r, g^r)
        let private_key = Felt::from(12345u64);

        let generator = krusty_kms_crypto::StarkCurve::generator();
        let public_key = krusty_kms_crypto::StarkCurve::mul_generator(&private_key);

        // Encrypt 0: C = (y^r, g^r) for some random r
        let r = Felt::from(999u64);
        let r_point = krusty_kms_crypto::StarkCurve::mul(&r, Some(&generator));
        let y_r = krusty_kms_crypto::StarkCurve::mul(&r, Some(&public_key));

        let cipher = CipherBalance { l: y_r, r: r_point };

        let decrypted = decrypt_cipher_balance_with_limit(&private_key, &cipher, 1_000).unwrap();
        assert_eq!(decrypted, 0);
    }

    #[test]
    fn test_decrypt_small_balance() {
        let private_key = Felt::from(12345u64);

        let generator = krusty_kms_crypto::StarkCurve::generator();
        let public_key = krusty_kms_crypto::StarkCurve::mul_generator(&private_key);

        // Encrypt balance 5: C = (g^5 * y^r, g^r)
        let r = Felt::from(999u64);
        let r_point = krusty_kms_crypto::StarkCurve::mul(&r, Some(&generator));
        let y_r = krusty_kms_crypto::StarkCurve::mul(&r, Some(&public_key));
        let g_m = krusty_kms_crypto::StarkCurve::mul(&Felt::from(5u64), Some(&generator));
        let l = krusty_kms_crypto::StarkCurve::add(&g_m, &y_r);

        let cipher = CipherBalance { l, r: r_point };

        let decrypted = decrypt_cipher_balance_with_limit(&private_key, &cipher, 1_000).unwrap();
        assert_eq!(decrypted, 5);
    }

    #[test]
    fn test_erc20_to_tongo_exact() {
        assert_eq!(erc20_to_tongo(1000, 10).unwrap(), 100);
    }

    #[test]
    fn test_erc20_to_tongo_ceiling() {
        assert_eq!(erc20_to_tongo(1001, 10).unwrap(), 101);
        assert_eq!(erc20_to_tongo(1009, 10).unwrap(), 101);
    }

    #[test]
    fn test_erc20_to_tongo_rate_one() {
        assert_eq!(erc20_to_tongo(42, 1).unwrap(), 42);
    }

    #[test]
    fn test_erc20_to_tongo_rate_greater_than_amount() {
        assert_eq!(erc20_to_tongo(5, 100).unwrap(), 1);
    }

    #[test]
    fn test_erc20_to_tongo_zero_amount() {
        assert_eq!(erc20_to_tongo(0, 10).unwrap(), 0);
    }

    #[test]
    fn test_tongo_to_erc20_basic() {
        assert_eq!(tongo_to_erc20(100, 10).unwrap(), 1000);
    }

    #[test]
    fn test_tongo_to_erc20_rate_one() {
        assert_eq!(tongo_to_erc20(42, 1).unwrap(), 42);
    }

    #[test]
    fn test_tongo_to_erc20_zero_amount() {
        assert_eq!(tongo_to_erc20(0, 10).unwrap(), 0);
    }

    #[test]
    fn test_roundtrip_conversion() {
        let rate = 1000u128;
        let original_tongo = 50u128;
        let erc20 = tongo_to_erc20(original_tongo, rate).unwrap();
        let back = erc20_to_tongo(erc20, rate).unwrap();
        assert_eq!(back, original_tongo);
    }

    #[test]
    fn test_decrypt_balance_with_zero_private_key_uses_identity_not_cipher_r() {
        let private_key = Felt::ZERO;
        let generator = krusty_kms_crypto::StarkCurve::generator();
        let r = Felt::from(999u64);
        let plaintext = Felt::from(7u64);

        let cipher = CipherBalance {
            l: krusty_kms_crypto::StarkCurve::mul(&plaintext, Some(&generator)),
            r: krusty_kms_crypto::StarkCurve::mul(&r, Some(&generator)),
        };

        let decrypted = decrypt_cipher_balance_with_limit(&private_key, &cipher, 1_000).unwrap();
        assert_eq!(decrypted, 7);
    }

    #[test]
    fn test_erc20_to_tongo_rejects_zero_rate() {
        assert!(erc20_to_tongo(1000, 0).is_err());
    }

    #[test]
    fn test_tongo_to_erc20_rejects_overflow() {
        assert!(tongo_to_erc20(u128::MAX, 2).is_err());
    }
}
