//! BIP-44 key derivation for Starknet, Tongo, and Nostr accounts.
//!
//! Derives keys using BIP-32 with secp256k1, then grinds the result
//! to produce a valid Stark curve scalar.
//!
//! # Memory
//!
//! Seeds, private keys, chain codes, and HMAC outputs live only in
//! `Zeroizing` arrays, `k256` scalars and `crypto-bigint` integers held in
//! `Zeroizing`, and the crate's internal wiped HMAC (`zeroizing_hmac`). Not wiped:
//! copies the compiler makes when it moves a value, register spills, and
//! temporaries inside `k256`, `crypto-bigint`, and the SHA-2 functions. The
//! keys these functions return (`Felt`, `[u8; 32]`) are the caller's to wipe.

use crate::mnemonic::mnemonic_to_seed;
use crate::zeroizing_hmac::hmac;
use crypto_bigint::{CtLt, NonZero, U256};
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::{ops::Reduce, Curve};
use k256::{FieldBytes, Scalar, Secp256k1};
use krusty_kms_common::{KmsError, Result, SecretFelt};
use sha2::{Digest, Sha256, Sha512};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type DerivedKeyPair = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

/// Tongo coin type for BIP-44 derivation path.
pub const TONGO_COIN_TYPE: u32 = 5454;

/// Starknet coin type for BIP-44 derivation path (SNIP-44).
pub const STARKNET_COIN_TYPE: u32 = 9004;

/// Nostr coin type for BIP-44 derivation path (SLIP-44 standard).
///
/// Nostr uses secp256k1 keys directly (no grinding required).
/// Derivation path: `m/44'/1237'/account'/0/index`
pub const NOSTR_COIN_TYPE: u32 = 1237;

/// Starknet curve order n, the modulus of a ground key.
const STARK_ORDER: NonZero<U256> = NonZero::<U256>::new_unwrap(U256::from_be_hex(
    "0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f",
));

/// Grinding's rejection bound `2^256 - (2^256 mod n)`. As n is odd,
/// `2^256 mod n = ((2^256 - 1) mod n) + 1`, so the bound is computed in 256 bits.
const GRIND_LIMIT: U256 = U256::MAX.wrapping_sub(&U256::MAX.rem(&STARK_ORDER));

/// A Tongo keypair (private key + public key).
///
/// The private key is wrapped in `SecretFelt` which ensures it is
/// zeroized when the keypair is dropped.
#[derive(Clone)]
pub struct TongoKeyPair {
    pub private_key: SecretFelt,
    pub public_key: ProjectivePoint,
}

impl core::fmt::Debug for TongoKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TongoKeyPair")
            .field("private_key", &"***")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// Derive a private key from a mnemonic with a custom coin type.
///
/// # Arguments
/// * `mnemonic` - BIP-39 mnemonic phrase
/// * `index` - Address index (default: 0)
/// * `account_index` - Account index (default: 0)
/// * `coin_type` - BIP-44 coin type (e.g., 5454 for Tongo, 9004 for Starknet)
/// * `passphrase` - Optional passphrase (default: empty)
///
/// # Derivation Path
/// `m/44'/{coin_type}'/account_index'/0/index`
///
/// # Errors
///
/// Returns [`KmsError`] if:
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
    require_unhardened_component(index, "index")?;
    require_unhardened_component(account_index, "account_index")?;
    require_unhardened_component(coin_type, "coin_type")?;

    let seed = Zeroizing::new(mnemonic_to_seed(mnemonic, passphrase.unwrap_or(""))?);

    // Derive master key from seed
    let master = derive_master_key(seed.as_ref())?;

    // BIP-44 path: m/44'/{coin_type}'/account_index'/0/index
    let path = [
        44 | 0x8000_0000,            // purpose (hardened)
        coin_type | 0x8000_0000,     // coin_type (hardened)
        account_index | 0x8000_0000, // account (hardened)
        0,                           // change
        index,                       // address_index
    ];

    let derived = derive_path(&master.0, &master.1, &path)?;

    // Grind the key to ensure it's in the valid range
    let ground_key = grind_key(&derived.0)?;

    Ok(ground_key)
}

/// Derive a Tongo private key from a mnemonic.
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
/// Returns [`KmsError`] if:
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

/// Derive a keypair from a mnemonic with a custom coin type.
///
/// # Errors
///
/// Returns [`KmsError`] if:
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
    let private_key =
        derive_private_key_with_coin_type(mnemonic, index, account_index, coin_type, passphrase)?;
    let public_key = compute_public_key(&private_key)?;

    Ok(TongoKeyPair {
        private_key: SecretFelt::new(private_key),
        public_key,
    })
}

/// Derive a Tongo keypair from a mnemonic.
///
/// # Errors
///
/// Returns [`KmsError`] if:
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

/// A Nostr keypair (raw secp256k1 private key as bytes).
///
/// The private key is zeroized when the keypair is dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NostrKeyPair {
    /// 32-byte secp256k1 private key
    pub private_key: [u8; 32],
    /// 32-byte x-only public key (BIP-340 format)
    #[zeroize(skip)]
    pub public_key: [u8; 32],
}

impl core::fmt::Debug for NostrKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NostrKeyPair")
            .field("private_key", &"***")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// Derive a Nostr private key from a mnemonic.
///
/// Unlike Tongo keys, Nostr keys are raw secp256k1 scalars without grinding.
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
/// Returns [`KmsError`] if:
/// - Mnemonic is invalid (`InvalidMnemonic`)
/// - Key derivation fails (`CryptoError`)
pub fn derive_nostr_private_key(
    mnemonic: &str,
    index: u32,
    account_index: u32,
    passphrase: Option<&str>,
) -> Result<[u8; 32]> {
    require_unhardened_component(index, "index")?;
    require_unhardened_component(account_index, "account_index")?;

    let seed = Zeroizing::new(mnemonic_to_seed(mnemonic, passphrase.unwrap_or(""))?);

    // Derive master key from seed
    let master = derive_master_key(seed.as_ref())?;

    // BIP-44 path: m/44'/1237'/account_index'/0/index
    let path = [
        44 | 0x8000_0000,              // purpose (hardened)
        NOSTR_COIN_TYPE | 0x8000_0000, // coin_type (hardened) - 1237 for Nostr
        account_index | 0x8000_0000,   // account (hardened)
        0,                             // change
        index,                         // address_index
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
/// Returns [`KmsError`] if:
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
        .map_err(|e| KmsError::CryptoError(format!("Invalid secp256k1 key: {}", e)))?;
    let verifying_key = signing_key.verifying_key();

    // Get x-only public key (BIP-340 format used by Nostr)
    let point = verifying_key.to_sec1_point(false); // uncompressed
    let x_bytes = point
        .x()
        .ok_or_else(|| KmsError::CryptoError("Failed to get x coordinate".to_string()))?;

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(x_bytes);

    Ok(NostrKeyPair {
        private_key,
        public_key,
    })
}

/// Derive a Starknet private key from an Ethereum private key using the
/// "double derivation" scheme used by old Argent wallets.
///
/// Derivation:
/// 1. Use ETH private key bytes, leading zero bytes stripped, as a new BIP-32
///    master seed (matches Argent X)
/// 2. Derive Starknet key at `m/44'/9004'/0'/0/{index}` from the second tree
/// 3. `grindKey` the result to produce a valid Stark scalar
///
/// # Arguments
/// * `eth_private_key` - 32-byte Ethereum private key (from m/44'/60'/0'/0/0)
/// * `index` - Address index (default: 0)
/// * `account_index` - Account index (default: 0)
pub fn derive_stark_from_eth_key(
    eth_private_key: &[u8; 32],
    index: u32,
    account_index: u32,
) -> Result<Felt> {
    require_unhardened_component(index, "index")?;
    require_unhardened_component(account_index, "account_index")?;

    // Argent X seeds the second tree with the ETH key as a number
    // (`BigNumber.from(secret).toHexString()`), so leading zero bytes are
    // dropped. Seeding with all 32 bytes diverges for ~1 key in 256.
    let first = eth_private_key
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(eth_private_key.len());
    let master = derive_master_key(&eth_private_key[first..])?;

    // Derive at m/44'/9004'/account'/0/index (same path as standard Starknet)
    let path = [
        44 | 0x8000_0000,
        STARKNET_COIN_TYPE | 0x8000_0000,
        account_index | 0x8000_0000,
        0,
        index,
    ];

    let derived = derive_path(&master.0, &master.1, &path)?;
    grind_key(&derived.0)
}

/// Derive a Starknet private key from a mnemonic using old Argent's double
/// derivation scheme.
///
/// This is the full pipeline:
/// 1. Mnemonic → BIP-39 seed (no passphrase)
/// 2. Seed → raw BIP-32 key at m/44'/60'/0'/0/0 (NO grindKey — this is an
///    ETH key, not a Stark key; ethers.js returns the raw secp256k1 scalar)
/// 3. Raw ETH key bytes → re-seed BIP-32 → m/44'/9004'/0'/0/{index}
/// 4. grindKey → Stark private key
pub fn derive_argent_legacy_private_key(
    mnemonic: &str,
    index: u32,
    account_index: u32,
) -> Result<Felt> {
    // Step 1: BIP-39 seed (no passphrase, matching ethers.js HDNodeWallet.fromPhrase)
    let seed = Zeroizing::new(mnemonic_to_seed(mnemonic, "")?);

    // Step 2: Derive raw BIP-32 key at m/44'/60'/0'/0/0 WITHOUT grinding
    // ethers.js returns the secp256k1 private key as-is
    let master = derive_master_key(seed.as_ref())?;
    let eth_path = [
        44 | 0x8000_0000, // purpose
        60 | 0x8000_0000, // ETH coin type
        0x8000_0000,      // account 0
        0,                // change
        0,                // index 0
    ];
    let eth_derived = derive_path(&master.0, &master.1, &eth_path)?;
    // NO grind_key here — ethersWallet.privateKey is the raw BIP-32 derived key

    // Step 3-4: Use ETH key as seed for second BIP-32 tree, then grind
    derive_stark_from_eth_key(&eth_derived.0, index, account_index)
}

/// Derive master key from seed using HMAC-SHA512 with "Bitcoin seed" key.
///
/// This matches the Swift implementation which uses "Bitcoin seed" for BIP-32.
///
/// # Cyclomatic Complexity: 1
fn derive_master_key(seed: &[u8]) -> Result<DerivedKeyPair> {
    let output = hmac::<Sha512, 64>(b"Bitcoin seed", &[seed])?;
    Ok(split_key_and_chain(&output))
}

/// Split a BIP-32 HMAC output `I` into `(IL, IR)`.
fn split_key_and_chain(output: &[u8; 64]) -> DerivedKeyPair {
    let mut key = Zeroizing::new([0u8; 32]);
    let mut chain_code = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&output[..32]);
    chain_code.copy_from_slice(&output[32..]);
    (key, chain_code)
}

/// Derive a child key using BIP-32 derivation with secp256k1.
///
/// This matches the Swift implementation which uses secp256k1 for HD derivation:
/// - Hardened: HMAC-SHA512(chain_code, 0x00 || priv || index)
/// - Non-hardened: HMAC-SHA512(chain_code, compressed_pubkey || index)
/// - child_key = (IL + parent_key) mod secp256k1_n
///
/// # Cyclomatic Complexity: 3
/// Reject caller-supplied path components with the hardened bit set.
///
/// Path builders OR `0x8000_0000` into hardened components, so a value that
/// already carries the bit would silently alias to a *different* caller's
/// value (e.g. `account_index` x and x|0x8000_0000 derive the same key). For
/// the non-hardened address index the bit would silently switch to hardened
/// derivation. Either way, reject rather than alias.
pub(crate) fn require_unhardened_component(value: u32, field: &str) -> Result<()> {
    if value & 0x8000_0000 != 0 {
        return Err(KmsError::InvalidDerivationPath(format!(
            "{field} {value} has the BIP-32 hardened bit set (must be < 2^31)"
        )));
    }
    Ok(())
}

fn derive_child(key: &[u8; 32], chain_code: &[u8; 32], index: u32) -> Result<DerivedKeyPair> {
    let index_bytes = index.to_be_bytes();
    let output = if (index & 0x8000_0000) != 0 {
        // Hardened derivation: 0x00 || priv || index
        hmac::<Sha512, 64>(chain_code, &[&[0x00][..], key, &index_bytes])?
    } else {
        // Non-hardened: compressed secp256k1 public key || index
        let signing_key = SigningKey::from_bytes(key.into())
            .map_err(|e| KmsError::CryptoError(format!("Invalid secp256k1 key: {}", e)))?;
        let compressed_pubkey = signing_key.verifying_key().to_sec1_point(true);
        hmac::<Sha512, 64>(chain_code, &[compressed_pubkey.as_bytes(), &index_bytes])?
    };
    let (mut derived_key, derived_chain) = split_key_and_chain(&output);
    let child = child_scalar(&derived_key, key)?;
    let mut child_bytes = child.to_bytes();
    derived_key.copy_from_slice(&child_bytes);
    child_bytes.as_mut_slice().zeroize();
    Ok((derived_key, derived_chain))
}

/// BIP-32's `parse256(IL) + k_par (mod n)`, rejecting `IL >= n` and a zero
/// child. Spec says try the next index; for a fixed path we return an error.
///
/// The parent is reduced mod n rather than rejected, as the earlier
/// big-integer code did, so an out-of-range master key (never validated)
/// still derives the same child. `IL` is range-checked in constant time as a
/// wiped `U256`, and both operands are reduced through borrows, so neither
/// leaves an owned, unwiped `FieldBytes` copy.
fn child_scalar(il: &[u8; 32], parent: &[u8; 32]) -> Result<Zeroizing<Scalar>> {
    let il = Zeroizing::new(U256::from_be_slice(il));
    if !il.ct_lt(Secp256k1::ORDER.as_ref()).to_bool() {
        let reason = "BIP-32 child derivation failed: IL >= curve order n";
        return Err(KmsError::CryptoError(reason.to_string()));
    }
    let il = Zeroizing::new(<Scalar as Reduce<U256>>::reduce(&il));
    let parent = Zeroizing::new(<Scalar as Reduce<FieldBytes>>::reduce(parent.into()));
    let child = Zeroizing::new(*il + *parent);
    if bool::from(child.is_zero()) {
        return Err(KmsError::CryptoError(
            "BIP-32 child derivation failed: derived key is zero".to_string(),
        ));
    }
    Ok(child)
}

/// Derive a key along a BIP-44 path.
///
/// # Cyclomatic Complexity: 1
fn derive_path(
    master_key: &[u8; 32],
    master_chain: &[u8; 32],
    path: &[u32],
) -> Result<DerivedKeyPair> {
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
pub fn grind_key(key_seed: &[u8; 32]) -> Result<Felt> {
    // Use u8 counter like Swift implementation
    for i in 0u8..=255 {
        // Hash keySeed || i (single byte)
        let mut digest = Sha256::new_with_prefix(key_seed)
            .chain_update([i])
            .finalize();
        let candidate = Zeroizing::new(U256::from_be_slice(&digest));
        digest.as_mut_slice().zeroize();

        // Check if candidate < GRIND_LIMIT (avoids bias)
        if *candidate >= GRIND_LIMIT {
            continue;
        }
        // Take modulo to get final Stark private key
        let k = Zeroizing::new(candidate.rem(&STARK_ORDER));

        // Reject the zero scalar (invalid private key); try the next counter.
        if *k == U256::ZERO {
            continue;
        }

        // Convert to 32-byte array (big-endian)
        let mut k_bytes: [u8; 32] = k.to_be_bytes().into();
        let key = Felt::from_bytes_be(&k_bytes);
        k_bytes.zeroize();
        return Ok(key);
    }

    Err(KmsError::CryptoError(
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
    // Use the standard Stark curve generator and scalar multiplication from krusty-kms-crypto
    // This avoids duplicating constants and eliminates unwrap() calls
    Ok(krusty_kms_crypto::StarkCurve::mul_generator(private_key))
}

#[cfg(test)]
mod reference_test;

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str =
        "habit hope tip crystal because grunt nation idea electric witness alert like";

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
        let keypair =
            derive_keypair_with_coin_type(TEST_MNEMONIC, 0, 0, TONGO_COIN_TYPE, None).unwrap();
        let standard = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        assert_eq!(keypair.private_key, standard.private_key);
    }

    #[test]
    fn test_derive_keypair_with_starknet_coin_type() {
        let keypair =
            derive_keypair_with_coin_type(TEST_MNEMONIC, 0, 0, STARKNET_COIN_TYPE, None).unwrap();
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
        // Nostr keys should be different from Tongo keys (different coin type, no grinding)
        let nostr = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let tongo = derive_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();

        // Convert Felt to bytes for comparison
        let tongo_bytes = tongo.private_key.expose_secret().to_bytes_be();
        assert_ne!(nostr.private_key.as_slice(), tongo_bytes.as_slice());
    }

    #[test]
    fn test_nostr_keypair_debug_redacts_private_key() {
        let keypair = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let debug = format!("{:?}", keypair);
        assert!(debug.contains("private_key: \"***\""));
        let priv_hex = hex::encode(keypair.private_key);
        assert!(!debug.contains(&priv_hex));
    }

    #[test]
    fn test_nostr_passphrase_changes_keys() {
        let without = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, None).unwrap();
        let with = derive_nostr_keypair(TEST_MNEMONIC, 0, 0, Some("test")).unwrap();
        assert_ne!(without.private_key, with.private_key);
    }
}
