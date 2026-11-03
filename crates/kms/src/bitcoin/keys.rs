//! BIP-84 key derivation and the P2WPKH signer shared by PSBT and BIP-322.

use super::bech32::encode_segwit_v0;
use super::bip32;
use super::tx::SIGHASH_ALL;
use crate::derivation::require_unhardened_component;
use crate::mnemonic::mnemonic_to_seed;
use bitcoin_hashes::{hash160, Hash as _};
use ecdsa::hazmat::sign_prehashed_rfc6979;
use k256::ecdsa::{Signature, SigningKey};
use k256::Secp256k1;
use krusty_kms_common::{KmsError, Result};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// SLIP-44 coin type for Bitcoin mainnet, used in `m/84'/0'/account'/change/index`.
pub const BITCOIN_COIN_TYPE: u32 = 0;

/// BIP-84 purpose (native segwit P2WPKH).
const BIP84_PURPOSE: u32 = 84;
const HARDENED: u32 = 0x8000_0000;
const MAINNET_HRP: &str = "bc";
/// Signing attempts before low-R grinding gives up. Each attempt is low-R
/// with probability 1/2, so hitting the bound means a broken signer.
const MAX_LOW_R_ATTEMPTS: u32 = 256;

/// A BIP-84 mainnet P2WPKH keypair.
///
/// The private key is zeroized when the keypair is dropped, and `Debug`
/// redacts it. The other fields are public.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BitcoinP2wpkhKeyPair {
    /// 32-byte secp256k1 private key.
    pub private_key: [u8; 32],
    /// 33-byte compressed SEC1 public key.
    #[zeroize(skip)]
    pub public_key: [u8; 33],
    /// Lowercase `bc1q…` P2WPKH address of `public_key`.
    #[zeroize(skip)]
    pub address: String,
    /// Derivation path, e.g. `m/84'/0'/0'/0/0`.
    #[zeroize(skip)]
    pub path: String,
}

impl core::fmt::Debug for BitcoinP2wpkhKeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BitcoinP2wpkhKeyPair")
            .field("private_key", &"***")
            .field("public_key", &self.public_key)
            .field("address", &self.address)
            .field("path", &self.path)
            .finish()
    }
}

/// Derive the BIP-84 mainnet P2WPKH keypair at
/// `m/84'/0'/account_index'/change/address_index`.
///
/// `change` is 0 for receiving addresses and 1 for change addresses.
///
/// # Errors
///
/// - `InvalidMnemonic` when the mnemonic is not valid BIP-39
/// - `InvalidDerivationPath` when `account_index` or `address_index` has the
///   hardened bit set, or `change` is not 0 or 1
/// - `CryptoError` when BIP-32 derivation hits an invalid child key
///
/// BIP-32 runs on `k256` scalars and wiped buffers (see `bip32`), not on the
/// shared `BigUint` helpers.
pub fn derive_bitcoin_p2wpkh_keypair(
    mnemonic: &str,
    account_index: u32,
    change: u32,
    address_index: u32,
    passphrase: Option<&str>,
) -> Result<BitcoinP2wpkhKeyPair> {
    require_unhardened_component(account_index, "account_index")?;
    require_unhardened_component(address_index, "address_index")?;
    if change > 1 {
        return Err(KmsError::InvalidDerivationPath(format!(
            "change {change} must be 0 (receiving) or 1 (change)"
        )));
    }

    let seed = Zeroizing::new(mnemonic_to_seed(mnemonic, passphrase.unwrap_or(""))?);
    let path = [
        BIP84_PURPOSE | HARDENED,
        BITCOIN_COIN_TYPE | HARDENED,
        account_index | HARDENED,
        change,
        address_index,
    ];
    let private_key = bip32::derive_private_key(seed.as_ref(), &path)?;
    let signer = P2wpkhSigner::new(&private_key)?;

    Ok(BitcoinP2wpkhKeyPair {
        private_key: *private_key,
        public_key: signer.public_key,
        address: signer.address()?,
        path: format!(
            "m/{BIP84_PURPOSE}'/{BITCOIN_COIN_TYPE}'/{account_index}'/{change}/{address_index}"
        ),
    })
}

/// A secp256k1 key viewed as the owner of one P2WPKH output script.
pub(super) struct P2wpkhSigner {
    signing_key: SigningKey,
    pub(super) public_key: [u8; 33],
    pub(super) pubkey_hash: [u8; 20],
}

impl P2wpkhSigner {
    pub(super) fn new(private_key: &[u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_slice(private_key)
            .map_err(|e| KmsError::InvalidPrivateKey(format!("Invalid secp256k1 key: {e}")))?;
        let public_key: [u8; 33] = signing_key
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .map_err(|_| KmsError::CryptoError("compressed public key is not 33 bytes".into()))?;
        let pubkey_hash = hash160::Hash::hash(&public_key).to_byte_array();
        Ok(Self {
            signing_key,
            public_key,
            pubkey_hash,
        })
    }

    /// The witness v0 key-hash output script: `OP_0 PUSH20 <hash160(pubkey)>`.
    pub(super) fn script_pubkey(&self) -> Vec<u8> {
        let mut script = Vec::with_capacity(22);
        script.extend([0x00, 0x14]);
        script.extend(self.pubkey_hash);
        script
    }

    pub(super) fn address(&self) -> Result<String> {
        encode_segwit_v0(MAINNET_HRP, &self.pubkey_hash)
    }

    /// Sign a SIGHASH_ALL digest: DER-encoded low-R, low-S ECDSA followed by
    /// the sighash byte, as placed in a witness or a PSBT partial signature.
    /// The result is at most 71 bytes.
    pub(super) fn sign_sighash_all(&self, sighash: &[u8; 32]) -> Result<Vec<u8>> {
        let mut encoded = self.sign_low_r(sighash)?.to_der().as_bytes().to_vec();
        encoded.push(SIGHASH_ALL);
        Ok(encoded)
    }

    /// Bitcoin Core's `CKey::Sign` with `grind = true`: plain RFC 6979 first,
    /// then RFC 6979 with 32 bytes of additional data that are zero except
    /// for a little-endian counter (1, 2, ...) in the first four, until `r`
    /// is below 2^255 and needs no DER padding byte. RFC 6979 section 3.6
    /// appends the data after the reduced digest, exactly where
    /// libsecp256k1's `nonce_function_rfc6979` puts `data32`, so the bytes
    /// match Core's.
    fn sign_low_r(&self, sighash: &[u8; 32]) -> Result<Signature> {
        let secret = self.signing_key.as_nonzero_scalar();
        let mut extra_entropy = [0u8; 32];
        for counter in 0..MAX_LOW_R_ATTEMPTS {
            extra_entropy[..4].copy_from_slice(&counter.to_le_bytes());
            let additional_data: &[u8] = if counter == 0 { &[] } else { &extra_entropy };
            let (signature, _) =
                sign_prehashed_rfc6979::<Secp256k1, Sha256>(secret, sighash, additional_data);
            // k256 already normalizes; keep low-S explicit because BIP-146
            // makes a high-S signature non-standard.
            let signature = signature.normalize_s();
            if signature
                .to_bytes()
                .first()
                .is_some_and(|byte| *byte < 0x80)
            {
                return Ok(signature);
            }
        }
        Err(KmsError::CryptoError(format!(
            "no low-R ECDSA signature after {MAX_LOW_R_ATTEMPTS} attempts"
        )))
    }
}
