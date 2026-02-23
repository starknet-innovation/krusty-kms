//! BIP-44 key derivation for TONGO accounts.
//!
//! This implementation follows the same approach as the Swift `WalletSDK`:
//! 1. Use standard BIP-32 derivation with secp256k1 (Bitcoin curve)
//! 2. At the end, grind the secp256k1 private key to make it valid for Stark curve

use crate::mnemonic::mnemonic_to_seed;
use ghoul_common::{GhoulError, Result, SecretFelt};
use hmac::{Hmac, Mac};
use k256::ecdsa::SigningKey;
use num_bigint::BigUint;
use num_traits::Num;
use sha2::{Digest, Sha256, Sha512};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type HmacSha512 = Hmac<Sha512>;

/// TONGO coin type for BIP-44 derivation path.
pub const TONGO_COIN_TYPE: u32 = 5454;

/// Starknet coin type for BIP-44 derivation path (SNIP-44).
pub const STARKNET_COIN_TYPE: u32 = 9004;

/// TONGO viewing/decryption coin type for BIP-44 derivation path.
///
/// This enables a dual-key model:
/// - Ownership/Spending key: `TONGO_COIN_TYPE` (5454)
/// - Viewing/Decryption key: `TONGO_VIEW_COIN_TYPE` (5353)
///
/// The viewing key can be used by wallets to decrypt balances and memos
/// without exposing the ownership/spending private key for read-only flows.
pub const TONGO_VIEW_COIN_TYPE: u32 = 5353;

/// Nostr coin type for BIP-44 derivation path (SLIP-44 standard).
///
/// Nostr uses secp256k1 keys directly (no grinding required).
/// Derivation path: `m/44'/1237'/account'/0/index`
pub const NOSTR_COIN_TYPE: u32 = 1237;

/// Starknet curve order (from starknet-crypto).
const CURVE_ORDER: &str = "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f";

/// A TONGO keypair (private key + public key).
///
/// The private key is wrapped in `SecretFelt` which ensures it is
/// zeroized when the keypair is dropped.
#[derive(Debug, Clone)]
pub struct TongoKeyPair {
    pub private_key: SecretFelt,
    pub public_key: ProjectivePoint,
}

/// Derive a private key from a mnemonic with a custom coin type.
///
/// # Arguments
/// * `mnemonic` - BIP-39 mnemonic phrase
/// * `index` - Address index (default: 0)
/// * `account_index` - Account index (default: 0)
/// * `coin_type` - BIP-44 coin type (e.g., 5454 for TONGO, 9004 for Starknet)
/// * `passphrase` - Optional passphrase (default: empty)
///
/// # Derivation Path
/// `m/44'/{coin_type}'/account_index'/0/index`
///
/// # Errors
///
/// Returns [`GhoulError`] if:
/// - Mnemonic is invalid (`InvalidMnemonic`)
/// - Key derivation fails (`CryptoError`)
/// - Key grinding fails (invalid curve point)
///
/// # Cyclomatic Complexity: 2
pub fn derive_private_key_with_coin_type(
    mnemonic: &str,
    index: u32,
    account_index: u32,
    coin_type: u32,
    passphrase: Option<&str>,
) -> Result<Felt> {
    let seed = Zeroizing::new(mnemonic_to_seed(mnemonic, passphrase.unwrap_or(""))?);

    // Derive master key from seed
    let master = derive_master_key(seed.as_ref())?;

    // BIP-44 path: m/44'/{coin_type}'/account_index'/0/index
    let path = [
        44 | 0x8000_0000,  // purpose (hardened)
        coin_type | 0x8000_0000, // coin_type (hardened)
        account_index | 0x8000_0000,   // account (hardened)
        0,  // change
        index, // address_index
    ];

    let derived = derive_path(&master.0, &master.1, &path)?;

    // Grind the key to ensure it's in the valid range
    let ground_key = grind_key(&derived.0)?;

    Ok(ground_key)
}

/// Derive a TONGO private key from a mnemonic.
///
/// # Arguments
/// * `mnemonic` - BIP-39 mnemonic phrase
/// * `index` - Address index (default: 0)
/// * `account_index` - Account index (default: 0)
/// * `passphrase` - Optional passphrase (default: empty)
///
/// # Derivation Path
/// `m/44'/5454'/account_index'/0/index`
///
/// # Errors
///
/// Returns [`GhoulError`] if:
/// - Mnemonic is invalid (`InvalidMnemonic`)
/// - Key derivation fails (`CryptoError`)
///
/// # Cyclomatic Complexity: 1
pub fn derive_private_key(
    mnemonic: &str,
    index: u32,
    account_index: u32,
    passphrase: Option<&str>,
) -> Result<Felt> {
    derive_private_key_with_coin_type(mnemonic, index, account_index, TONGO_COIN_TYPE, passphrase)
}

/// Derive a TONGO viewing private key from a mnemonic.
///
/// # Derivation Path
/// `m/44'/5353'/account_index'/0/index`
///
/// # Errors
///
/// Returns [`GhoulError`] if:
/// - Mnemonic is invalid (`InvalidMnemonic`)
/// - Key derivation fails (`CryptoError`)
/// - Key grinding fails (invalid curve point)
pub fn derive_view_private_key(
    mnemonic: &str,
    index: u32,
    account_index: u32,
    passphrase: Option<&str>,
) -> Result<Felt> {
    derive_private_key_with_coin_type(
        mnemonic,
        index,
        account_index,
        TONGO_VIEW_COIN_TYPE,
        passphrase,
    )
}

/// Derive a keypair from a mnemonic with a custom coin type.
///
/// # Errors
///
/// Returns [`GhoulError`] if:
/// - Mnemonic is invalid (`InvalidMnemonic`)
/// - Key derivation fails (`CryptoError`)
/// - Public key generation fails (point at infinity)
///
/// # Cyclomatic Complexity: 1
pub fn derive_keypair_with_coin_type(
    mnemonic: &str,
    index: u32,
    account_index: u32,
    coin_type: u32,
    passphrase: Option<&str>,
) -> Result<TongoKeyPair> {
    let private_key = derive_private_key_with_coin_type(mnemonic, index, account_index, coin_type, passphrase)?;
    let public_key = compute_public_key(&private_key)?;

    Ok(TongoKeyPair {
        private_key: SecretFelt::new(private_key),
        public_key,
    })
}

/// Derive a TONGO keypair from a mnemonic.
///
/// # Errors
///
/// Returns [`GhoulError`] if:
/// - Mnemonic is invalid (`InvalidMnemonic`)
/// - Key derivation fails (`CryptoError`)
///
/// # Cyclomatic Complexity: 1
pub fn derive_keypair(
    mnemonic: &str,
    index: u32,
    account_index: u32,
    passphrase: Option<&str>,
) -> Result<TongoKeyPair> {
    derive_keypair_with_coin_type(mnemonic, index, account_index, TONGO_COIN_TYPE, passphrase)
}

/// Derive a TONGO viewing keypair from a mnemonic.
///
/// # Derivation Path
/// `m/44'/5353'/account_index'/0/index`
///
/// # Errors
///
/// Returns [`GhoulError`] if:
/// - Mnemonic is invalid (`InvalidMnemonic`)
/// - Key derivation fails (`CryptoError`)
/// - Public key generation fails (point at infinity)
pub fn derive_view_keypair(
    mnemonic: &str,
    index: u32,
    account_index: u32,
    passphrase: Option<&str>,
) -> Result<TongoKeyPair> {
    derive_keypair_with_coin_type(
        mnemonic,
        index,
        account_index,
        TONGO_VIEW_COIN_TYPE,
        passphrase,
    )
}

/// A Nostr keypair (raw secp256k1 private key as bytes).
///
/// The private key is zeroized when the keypair is dropped.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct NostrKeyPair {
    /// 32-byte secp256k1 private key
    pub private_key: [u8; 32],
    /// 32-byte x-only public key (BIP-340 format)
    #[zeroize(skip)]
    pub public_key: [u8; 32],
}

/// Derive a Nostr private key from a mnemonic.
///
/// Unlike TONGO keys, Nostr keys are raw secp256k1 scalars without grinding.
/// This is compatible with other Nostr wallets that follow SLIP-44.
///
/// # Derivation Path
/// `m/44'/1237'/account_index'/0/index`
///
/// # Arguments
/// * `mnemonic` - BIP-39 mnemonic phrase
/// * `index` - Address index (default: 0)
/// * `account_index` - Account index (default: 0)
/// * `passphrase` - Optional passphrase (default: empty)
///
/// # Errors
///
/// Returns [`GhoulError`] if:
/// - Mnemonic is invalid (`InvalidMnemonic`)
/// - Key derivation fails (`CryptoError`)
pub fn derive_nostr_private_key(
    mnemonic: &str,
    index: u32,
    account_index: u32,
    passphrase: Option<&str>,
) -> Result<[u8; 32]> {
    let seed = Zeroizing::new(mnemonic_to_seed(mnemonic, passphrase.unwrap_or(""))?);

    // Derive master key from seed
    let master = derive_master_key(seed.as_ref())?;

    // BIP-44 path: m/44'/1237'/account_index'/0/index
    let path = [
        44 | 0x8000_0000,         // purpose (hardened)
        NOSTR_COIN_TYPE | 0x8000_0000, // coin_type (hardened) - 1237 for Nostr
        account_index | 0x8000_0000,   // account (hardened)
        0,                        // change
        index,                    // address_index
    ];

    let derived = derive_path(&master.0, &master.1, &path)?;

    // Return raw secp256k1 key without grinding
    // Nostr uses secp256k1 directly, no conversion needed
    Ok(*derived.0)
}

/// Derive a Nostr keypair from a mnemonic.
///
/// Returns both private key and x-only public key (BIP-340 format).
///
/// # Derivation Path
/// `m/44'/1237'/account_index'/0/index`
///
/// # Errors
///
/// Returns [`GhoulError`] if:
/// - Mnemonic is invalid (`InvalidMnemonic`)
/// - Key derivation fails (`CryptoError`)
/// - Public key generation fails
pub fn derive_nostr_keypair(
    mnemonic: &str,
    index: u32,
    account_index: u32,
    passphrase: Option<&str>,
) -> Result<NostrKeyPair> {
    let private_key = derive_nostr_private_key(mnemonic, index, account_index, passphrase)?;

    // Derive secp256k1 public key
    let signing_key = SigningKey::from_bytes((&private_key).into())
        .map_err(|e| GhoulError::CryptoError(format!("Invalid secp256k1 key: {}", e)))?;
    let verifying_key = signing_key.verifying_key();

    // Get x-only public key (BIP-340 format used by Nostr)
    let point = verifying_key.to_encoded_point(false); // uncompressed
    let x_bytes = point.x().ok_or_else(|| {
        GhoulError::CryptoError("Failed to get x coordinate".to_string())
    })?;

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(x_bytes);

    Ok(NostrKeyPair {
        private_key,
        public_key,
    })
}

/// Derive master key from seed using HMAC-SHA512 with "Bitcoin seed" key.
///
/// This matches the Swift implementation which uses "Bitcoin seed" for BIP-32.
///
/// # Cyclomatic Complexity: 1
fn derive_master_key(seed: &[u8]) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)> {
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")
        .map_err(|e| GhoulError::CryptoError(e.to_string()))?;
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let mut key = Zeroizing::new([0u8; 32]);
    let mut chain_code = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..64]);

    Ok((key, chain_code))
}

/// Derive a child key using BIP-32 derivation with secp256k1.
///
/// This matches the Swift implementation which uses secp256k1 for HD derivation:
/// - Hardened: HMAC-SHA512(chain_code, 0x00 || priv || index)
/// - Non-hardened: HMAC-SHA512(chain_code, compressed_pubkey || index)
/// - child_key = (IL + parent_key) mod secp256k1_n
///
/// # Cyclomatic Complexity: 3
fn derive_child(key: &[u8; 32], chain_code: &[u8; 32], index: u32) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)> {
    let mut mac = HmacSha512::new_from_slice(chain_code)
        .map_err(|e| GhoulError::CryptoError(e.to_string()))?;

    let hardened = (index & 0x8000_0000) != 0;

    if hardened {
        // Hardened derivation: 0x00 || priv || index
        mac.update(&[0x00]);
        mac.update(key);
    } else {
        // Non-hardened: compressed secp256k1 public key || index
        let signing_key = SigningKey::from_bytes(key.into())
            .map_err(|e| GhoulError::CryptoError(format!("Invalid secp256k1 key: {}", e)))?;
        let verifying_key = signing_key.verifying_key();
        let compressed_pubkey = verifying_key.to_encoded_point(true); // compressed = true
        mac.update(compressed_pubkey.as_bytes()); // 33 bytes: 0x02/0x03 + x
    }

    mac.update(&index.to_be_bytes());
    let result = mac.finalize().into_bytes();

    // Split I into IL (left 32 bytes) and IR (right 32 bytes)
    let il = &result[..32];
    let ir = &result[32..64];

    // secp256k1 curve order
    let secp256k1_n = BigUint::from_bytes_be(&[
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ]);

    // BIP-32: child_key = (parse256(IL) + parent_key) mod n
    let il_num = BigUint::from_bytes_be(il);
    let parent_num = BigUint::from_bytes_be(key);
    let child_num = (il_num + parent_num) % &secp256k1_n;

    // Convert back to bytes (big-endian, padded to 32 bytes)
    let child_bytes = child_num.to_bytes_be();
    let mut derived_key = Zeroizing::new([0u8; 32]);
    let start = 32 - child_bytes.len().min(32);
    derived_key[start..].copy_from_slice(&child_bytes[..child_bytes.len().min(32)]);

    let mut derived_chain = Zeroizing::new([0u8; 32]);
    derived_chain.copy_from_slice(ir);

    Ok((derived_key, derived_chain))
}

/// Derive a key along a BIP-44 path.
///
/// # Cyclomatic Complexity: 1
fn derive_path(
    master_key: &[u8; 32],
    master_chain: &[u8; 32],
    path: &[u32],
) -> Result<(Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>)> {
    let mut key = Zeroizing::new(*master_key);
    let mut chain = Zeroizing::new(*master_chain);

    for &index in path {
        let (derived_key, derived_chain) = derive_child(&key, &chain, index)?;
        key = derived_key;
        chain = derived_chain;
    }

    Ok((key, chain))
}

/// Grind a secp256k1 private key to make it valid for the Stark curve.
///
/// This matches the Swift StarkGrind implementation:
/// 1. Hash keySeed || i (where i is a u8 counter)
/// 2. Check if hash < limit (where limit = 2^256 - (2^256 mod stark_order))
/// 3. Return hash mod stark_order
///
/// The key difference from scure-starknet: we append a single byte (u8) counter,
/// not a big-endian u32.
///
/// # Cyclomatic Complexity: 2
fn grind_key(key_seed: &[u8; 32]) -> Result<Felt> {
    // Stark curve order
    let stark_order = BigUint::from_str_radix(CURVE_ORDER, 16)
        .map_err(|e| GhoulError::CryptoError(e.to_string()))?;

    // sha256mask = 2^256
    let two256 = BigUint::from(1u32) << 256;

    // Rejection upper bound: 2^256 - (2^256 mod stark_order)
    let max_allowed = &two256 - (&two256 % &stark_order);

    // Use u8 counter like Swift implementation
    for i in 0u8..=255 {
        // Hash keySeed || i (single byte)
        let mut hasher = Sha256::new();
        hasher.update(key_seed);
        hasher.update(&[i]);
        let digest = hasher.finalize();

        let candidate = BigUint::from_bytes_be(&digest);

        // Check if candidate < max_allowed (avoids bias)
        if candidate < max_allowed {
            // Take modulo to get final Stark private key
            let k = candidate % &stark_order;

            // Convert to 32-byte array (big-endian)
            let k_bytes = k.to_bytes_be();
            let mut padded = [0u8; 32];
            let start = 32 - k_bytes.len().min(32);
            padded[start..].copy_from_slice(&k_bytes[..k_bytes.len().min(32)]);

            return Ok(Felt::from_bytes_be_slice(&padded));
        }
    }

    Err(GhoulError::CryptoError(
        "Failed to grind key after 256 iterations".to_string(),
    ))
}

/// Compute the Stark curve public key from a private key.
///
/// Uses scalar multiplication: public_key = G * private_key
/// where G is the Stark curve generator point.
///
/// Uses double-and-add algorithm for scalar multiplication.
///
/// # Cyclomatic Complexity: 1
fn compute_public_key(private_key: &Felt) -> Result<ProjectivePoint> {
    // Use the standard Stark curve generator and scalar multiplication from she-core
    // This avoids duplicating constants and eliminates unwrap() calls
    Ok(she_core::StarkCurve::mul_generator(private_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str = "habit hope tip crystal because grunt nation idea electric witness alert like";

    #[test]
    fn test_derive_private_key() {
        let result = derive_private_key(TEST_MNEMONIC, 0, 0, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_derive_keypair() {
        let keypair = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        assert_ne!(keypair.private_key, Felt::ZERO);
    }

    #[test]
    fn test_deterministic_derivation() {
        let keypair1 = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let keypair2 = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();

        assert_eq!(keypair1.private_key, keypair2.private_key);
    }

    #[test]
    fn test_different_indices_produce_different_keys() {
        let keypair0 = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let keypair1 = derive_keypair(TEST_MNEMONIC, 1, 0, None).unwrap();

        assert_ne!(keypair0.private_key, keypair1.private_key);
    }

    #[test]
    fn test_different_accounts_produce_different_keys() {
        let keypair_acc0 = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let keypair_acc1 = derive_keypair(TEST_MNEMONIC, 0, 1, None).unwrap();

        assert_ne!(keypair_acc0.private_key, keypair_acc1.private_key);
    }

    #[test]
    fn test_view_key_uses_different_coin_type() {
        let owner = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let view = derive_view_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        assert_ne!(owner.private_key, view.private_key);
    }

    #[test]
    fn test_derive_view_private_key() {
        let result = derive_view_private_key(TEST_MNEMONIC, 0, 0, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_derive_view_keypair() {
        let keypair = derive_view_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        assert_ne!(keypair.private_key, Felt::ZERO);
    }

    #[test]
    fn test_view_keypair_deterministic() {
        let keypair1 = derive_view_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let keypair2 = derive_view_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        assert_eq!(keypair1.private_key, keypair2.private_key);
    }

    #[test]
    fn test_passphrase_changes_keys() {
        let without_passphrase = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let with_passphrase = derive_keypair(TEST_MNEMONIC, 0, 0, Some("test_passphrase")).unwrap();
        assert_ne!(without_passphrase.private_key, with_passphrase.private_key);
    }

    #[test]
    fn test_empty_passphrase_same_as_none() {
        let with_none = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let with_empty = derive_keypair(TEST_MNEMONIC, 0, 0, Some("")).unwrap();
        assert_eq!(with_none.private_key, with_empty.private_key);
    }

    #[test]
    fn test_derive_keypair_with_coin_type() {
        let keypair = derive_keypair_with_coin_type(TEST_MNEMONIC, 0, 0, TONGO_COIN_TYPE, None).unwrap();
        let standard = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        assert_eq!(keypair.private_key, standard.private_key);
    }

    #[test]
    fn test_derive_keypair_with_starknet_coin_type() {
        let keypair = derive_keypair_with_coin_type(TEST_MNEMONIC, 0, 0, STARKNET_COIN_TYPE, None).unwrap();
        let tongo = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        // Different coin types should produce different keys
        assert_ne!(keypair.private_key, tongo.private_key);
    }

    #[test]
    fn test_invalid_mnemonic() {
        let result = derive_keypair("invalid mnemonic words that are not valid", 0, 0, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_view_key_indices() {
        let view0 = derive_view_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let view1 = derive_view_keypair(TEST_MNEMONIC, 1, 0, None).unwrap();
        assert_ne!(view0.private_key, view1.private_key);
    }

    #[test]
    fn test_different_view_key_accounts() {
        let view_acc0 = derive_view_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let view_acc1 = derive_view_keypair(TEST_MNEMONIC, 0, 1, None).unwrap();
        assert_ne!(view_acc0.private_key, view_acc1.private_key);
    }

    #[test]
    fn test_derive_nostr_private_key() {
        let result = derive_nostr_private_key(TEST_MNEMONIC, 0, 0, None);
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn test_derive_nostr_keypair() {
        let keypair = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        assert_ne!(keypair.private_key, [0u8; 32]);
        assert_ne!(keypair.public_key, [0u8; 32]);
    }

    #[test]
    fn test_nostr_keypair_deterministic() {
        let keypair1 = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let keypair2 = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        assert_eq!(keypair1.private_key, keypair2.private_key);
        assert_eq!(keypair1.public_key, keypair2.public_key);
    }

    #[test]
    fn test_nostr_different_indices() {
        let keypair0 = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let keypair1 = derive_nostr_keypair(TEST_MNEMONIC, 1, 0, None).unwrap();
        assert_ne!(keypair0.private_key, keypair1.private_key);
    }

    #[test]
    fn test_nostr_different_accounts() {
        let keypair_acc0 = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let keypair_acc1 = derive_nostr_keypair(TEST_MNEMONIC, 0, 1, None).unwrap();
        assert_ne!(keypair_acc0.private_key, keypair_acc1.private_key);
    }

    #[test]
    fn test_nostr_different_from_tongo() {
        // Nostr keys should be different from TONGO keys (different coin type, no grinding)
        let nostr = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let tongo = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();

        // Convert Felt to bytes for comparison
        let tongo_bytes = tongo.private_key.expose_secret().to_bytes_be();
        assert_ne!(nostr.private_key.as_slice(), tongo_bytes.as_slice());
    }

    #[test]
    fn test_nostr_passphrase_changes_keys() {
        let without = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let with = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, Some("test")).unwrap();
        assert_ne!(without.private_key, with.private_key);
    }
}
