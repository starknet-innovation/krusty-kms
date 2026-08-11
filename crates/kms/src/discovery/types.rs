//! Public types for account discovery: candidates, keypairs, and their
//! secret-including serializable views.

use krusty_kms_common::{KmsError, Result};
use serde::{Deserialize, Serialize};
use starknet_types_core::felt::Felt;
use std::fmt;
use zeroize::Zeroize;

/// Shared checks for the `private_key` hex field of discovery types.
///
/// Default `Serialize` omits private keys, so a serde round-trip yields an
/// empty `private_key`. These helpers make that state loud instead of letting
/// an empty string flow into signing or export paths.
fn require_private_key(private_key: &str) -> Result<&str> {
    if private_key.is_empty() {
        return Err(KmsError::InvalidPrivateKey(
            "candidate has no private key material (deserialized from public-only JSON?)"
                .to_string(),
        ));
    }
    Ok(private_key)
}

/// Verify that a candidate's private key actually derives its public key.
///
/// Deserialized discovery results are untrusted input: nothing guarantees the
/// `private_key` and `public_key` fields still belong together. Call this
/// before trusting a deserialized candidate in a recovery flow.
fn verify_key_binding(private_key: &str, public_key: &str) -> Result<()> {
    let private = Felt::from_hex(require_private_key(private_key)?)
        .map_err(|e| KmsError::InvalidPrivateKey(format!("invalid private key hex: {e}")))?;
    let expected_public = Felt::from_hex(public_key)
        .map_err(|e| KmsError::InvalidPublicKey(format!("invalid public key hex: {e}")))?;
    let derived_public = crate::stark_signing::stark_public_key(&private)?;
    if derived_public != expected_public {
        return Err(KmsError::InvalidPrivateKey(
            "private key does not derive the candidate's public key".to_string(),
        ));
    }
    Ok(())
}

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
    ///
    /// Errors when the candidate holds no key material — the state produced by
    /// deserializing the public-only JSON form — instead of handing back an
    /// empty string that would silently flow into signing or export paths.
    pub fn expose_private_key(&self) -> Result<&str> {
        require_private_key(&self.private_key)
    }

    /// Verify that `private_key` derives `public_key`.
    ///
    /// Candidates built by [`super::generate_candidates`] are consistent by
    /// construction; call this on candidates that crossed a serialization
    /// boundary before trusting them in a recovery flow. (The address itself
    /// is not recomputed here — a recovery flow confirms it on-chain.)
    pub fn verify_key_binding(&self) -> Result<()> {
        verify_key_binding(&self.private_key, &self.public_key)
    }

    /// Serializable view that includes the private key.
    ///
    /// Use only at explicit recovery / WASM boundaries that must return secrets.
    /// Errors when the candidate holds no key material.
    pub fn with_secrets(&self) -> Result<CandidateAccountWithSecrets<'_>> {
        Ok(CandidateAccountWithSecrets {
            wallet_type: self.wallet_type,
            class_hash: &self.class_hash,
            address: &self.address,
            public_key: &self.public_key,
            private_key: require_private_key(&self.private_key)?,
            derivation_index: self.derivation_index,
            derivation_path: &self.derivation_path,
            class_version: &self.class_version,
        })
    }
}

impl Drop for CandidateAccount {
    fn drop(&mut self) {
        self.private_key.zeroize();
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
    ///
    /// Errors when the keypair holds no key material (public-only round-trip).
    pub fn expose_private_key(&self) -> Result<&str> {
        require_private_key(&self.private_key)
    }

    /// Verify that `private_key` derives `public_key`.
    ///
    /// Call on keypairs that crossed a serialization boundary before trusting
    /// them in a recovery flow.
    pub fn verify_key_binding(&self) -> Result<()> {
        verify_key_binding(&self.private_key, &self.public_key)
    }

    /// Serializable view that includes the private key.
    ///
    /// Errors when the keypair holds no key material.
    pub fn with_secrets(&self) -> Result<DerivedKeypairWithSecrets<'_>> {
        Ok(DerivedKeypairWithSecrets {
            derivation_type: self.derivation_type,
            public_key: &self.public_key,
            private_key: require_private_key(&self.private_key)?,
            derivation_index: self.derivation_index,
            derivation_path: &self.derivation_path,
        })
    }
}

impl Drop for DerivedKeypair {
    fn drop(&mut self) {
        self.private_key.zeroize();
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
