//! Public types for account discovery: candidates, keypairs, and their
//! secret-including serializable views.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The type of wallet that created the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletType {
    /// Braavos: direct m/44'/9004'/0'/0/{index}, base deployment class hash.
    Braavos,
    /// Argent: direct m/44'/9004'/0'/0/{index}, Cairo 1 class hash.
    Argent,
    /// Argent legacy: double derivation via ETH key, Cairo 1 class hashes.
    ArgentLegacy,
    /// Argent Cairo 0: double derivation via ETH key, proxy + implementation pattern.
    ArgentCairo0,
    /// OpenZeppelin: direct m/44'/9004'/0'/0/{index}, OZ class hash.
    OpenZeppelin,
}

/// A candidate account address derived from a mnemonic.
///
/// Generated purely from cryptographic derivation — no network I/O.
/// Each candidate represents a possible on-chain account that may or may not
/// be deployed. Check deployment status via RPC to filter to actual accounts.
///
/// # Security
///
/// This struct contains the **private key** in the `private_key` field.
/// Callers must handle this securely — avoid logging, persist only in
/// encrypted storage, and zeroize when no longer needed.
///
/// Default `Serialize` **omits** `private_key`. Use [`Self::with_secrets`] (or
/// [`Self::expose_private_key`]) at intentional recovery boundaries.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateAccount {
    pub wallet_type: WalletType,
    /// The class hash used for address computation.
    pub class_hash: String,
    /// The computed account contract address.
    pub address: String,
    /// The Stark public key (x-coordinate).
    pub public_key: String,
    /// The Stark private key. Omitted from default Serialize; use
    /// [`Self::with_secrets`] when an API must return it.
    #[serde(default)]
    pub private_key: String,
    /// The HD derivation index used.
    pub derivation_index: u32,
    /// Human-readable derivation path description.
    pub derivation_path: String,
    /// The class hash version label (e.g., "v0.4.0", "proxy+v0.2.4").
    pub class_version: String,
}

impl fmt::Debug for CandidateAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CandidateAccount")
            .field("wallet_type", &self.wallet_type)
            .field("class_hash", &self.class_hash)
            .field("address", &self.address)
            .field("public_key", &self.public_key)
            .field("private_key", &"***")
            .field("derivation_index", &self.derivation_index)
            .field("derivation_path", &self.derivation_path)
            .field("class_version", &self.class_version)
            .finish()
    }
}

impl CandidateAccount {
    /// Intentional access to the private key hex string.
    pub fn expose_private_key(&self) -> &str {
        &self.private_key
    }

    /// Serializable view that includes the private key.
    ///
    /// Use only at explicit recovery / WASM boundaries that must return secrets.
    pub fn with_secrets(&self) -> CandidateAccountWithSecrets<'_> {
        CandidateAccountWithSecrets {
            wallet_type: self.wallet_type,
            class_hash: &self.class_hash,
            address: &self.address,
            public_key: &self.public_key,
            private_key: &self.private_key,
            derivation_index: self.derivation_index,
            derivation_path: &self.derivation_path,
            class_version: &self.class_version,
        }
    }
}

impl Serialize for CandidateAccount {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Public view: private_key is intentionally omitted.
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("CandidateAccount", 7)?;
        state.serialize_field("walletType", &self.wallet_type)?;
        state.serialize_field("classHash", &self.class_hash)?;
        state.serialize_field("address", &self.address)?;
        state.serialize_field("publicKey", &self.public_key)?;
        state.serialize_field("derivationIndex", &self.derivation_index)?;
        state.serialize_field("derivationPath", &self.derivation_path)?;
        state.serialize_field("classVersion", &self.class_version)?;
        state.end()
    }
}

/// Serializable candidate including the private key (recovery escape hatch).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateAccountWithSecrets<'a> {
    pub wallet_type: WalletType,
    pub class_hash: &'a str,
    pub address: &'a str,
    pub public_key: &'a str,
    pub private_key: &'a str,
    pub derivation_index: u32,
    pub derivation_path: &'a str,
    pub class_version: &'a str,
}

/// A unique keypair derived from a mnemonic for a specific derivation scheme.
///
/// Unlike `CandidateAccount`, this does NOT compute addresses. It's meant for
/// API-based account lookup — e.g., querying Argent's smart account API by
/// public key to find accounts whose addresses can't be derived locally
/// (because the salt was server-provided).
///
/// Default `Serialize` omits `private_key`. Use [`Self::with_secrets`] when an
/// intentional recovery boundary must include it.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DerivedKeypair {
    /// Which derivation scheme produced this keypair.
    pub derivation_type: DerivationType,
    /// The Stark public key (x-coordinate, hex).
    pub public_key: String,
    /// The Stark private key (hex). Omitted from default Serialize.
    #[serde(default)]
    pub private_key: String,
    /// The HD derivation index.
    pub derivation_index: u32,
    /// Human-readable derivation path.
    pub derivation_path: String,
}

impl fmt::Debug for DerivedKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedKeypair")
            .field("derivation_type", &self.derivation_type)
            .field("public_key", &self.public_key)
            .field("private_key", &"***")
            .field("derivation_index", &self.derivation_index)
            .field("derivation_path", &self.derivation_path)
            .finish()
    }
}

impl DerivedKeypair {
    /// Intentional access to the private key hex string.
    pub fn expose_private_key(&self) -> &str {
        &self.private_key
    }

    /// Serializable view that includes the private key.
    pub fn with_secrets(&self) -> DerivedKeypairWithSecrets<'_> {
        DerivedKeypairWithSecrets {
            derivation_type: self.derivation_type,
            public_key: &self.public_key,
            private_key: &self.private_key,
            derivation_index: self.derivation_index,
            derivation_path: &self.derivation_path,
        }
    }
}

impl Serialize for DerivedKeypair {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("DerivedKeypair", 4)?;
        state.serialize_field("derivationType", &self.derivation_type)?;
        state.serialize_field("publicKey", &self.public_key)?;
        state.serialize_field("derivationIndex", &self.derivation_index)?;
        state.serialize_field("derivationPath", &self.derivation_path)?;
        state.end()
    }
}

/// Serializable keypair including the private key (recovery escape hatch).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DerivedKeypairWithSecrets<'a> {
    pub derivation_type: DerivationType,
    pub public_key: &'a str,
    pub private_key: &'a str,
    pub derivation_index: u32,
    pub derivation_path: &'a str,
}

/// The derivation scheme used to produce a keypair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DerivationType {
    /// Standard BIP-44 m/44'/9004'/0'/0/{index} (used by Braavos, new Argent, OZ).
    Direct,
    /// Argent legacy double derivation: ETH key → re-seed → m/44'/9004'/0'/0/{index}.
    ArgentLegacy,
}
