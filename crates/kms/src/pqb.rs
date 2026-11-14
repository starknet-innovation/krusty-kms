// Portions ported from fireblocks-labs/pqb, Copyright (c) 2026 Fireblocks Ltd.
// MIT license: ../licenses/PQB-MIT.txt (included in this crate package).
//! PQB vault key management for the fixed real-puzzle `PQB` profile.
//!
//! Seeds, private keys and unselected menu signatures stay inside this module.
//! Public material is compatible with fireblocks-labs/pqb; QSB-HORS-v1 is a
//! different derivation profile and must never be substituted for it.
//!
//! # Authorization boundary
//!
//! These are stateless primitives. Before [`PqbVault::authorize`], the caller
//! must durably journal [`PqbRequest::digest`] as exposed and forever refuse a
//! different request for that vault, including after restore. The caller also
//! verifies funding, destinations, fees and grind solutions. Structural request
//! validation does **not** verify puzzles, execute Script or consult the chain.
//!
//! # Memory
//!
//! Owned seeds, secret scalars, SHA-2 states and disclosure buffers wipe on drop;
//! secret-bearing types have redacted Debug and no serialization or Clone.
//! SHA-1 and RIPEMD-160 secret-bearing hash states also wipe on drop.
//! Compiler-created copies and register spills are outside the guarantee. See `mnemonic` for BIP39 memory limitations.

mod key;
mod lock;
mod menu;
mod request;
#[cfg(test)]
mod tests;

use bitcoin_hashes::{hash160, Hash as _};
use krusty_kms_common::{KmsError, Result};
pub use request::{PqbDisclosure, PqbRequest, PqbSelection};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

/// A supported chain. Names are part of the frozen vault-seed binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PqbNetwork {
    /// Bitcoin mainnet (`main`).
    Mainnet,
    /// Bitcoin testnet4 (`testnet4`).
    Testnet4,
    /// Local regression-test chain (`regtest`).
    Regtest,
}
impl PqbNetwork {
    fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "main",
            Self::Testnet4 => "testnet4",
            Self::Regtest => "regtest",
        }
    }
    fn hrp(self) -> &'static str {
        match self {
            Self::Mainnet => "bc",
            Self::Testnet4 => "tb",
            Self::Regtest => "bcrt",
        }
    }
}

/// Public data for one vault; safe to give to a script builder or grinder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqbPublicMaterial {
    /// Exact 4,908-byte real-puzzle bare locking script.
    pub script: Vec<u8>,
    /// SHA256 of `script`.
    pub script_sha256: [u8; 32],
    /// Shared chained HORS table, in index order.
    pub commitments: [[u8; 20]; 109],
    /// Compressed SEC1 co-signing public key.
    pub cosig_public_key: [u8; 33],
    /// Pinning, round 0 and round 1 menus; no scalars or signatures.
    pub menus: [PqbPublicMenu; 3],
}

/// A menu's public commitments and grinder recovery points.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqbPublicMenu {
    /// Common signature r, big-endian.
    pub r: [u8; 32],
    /// SHA1 of each secret DER signature including its SIGHASH_ALL byte.
    pub commitments: Vec<[u8; 20]>,
    /// Points `(s/r)R` as uncompressed SEC1 bytes. Variants are ordered
    /// `(r,even), (r,odd), (r+n,even), (r+n,odd)` when those points exist.
    pub recovery_points: Vec<Vec<[u8; 65]>>,
}

/// A public deposit address and key. The private key remains inside the vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqbDeposit {
    /// Network-specific BIP173 address.
    pub address: String,
    /// P2WPKH output script.
    pub script_pubkey: Vec<u8>,
    /// Compressed SEC1 public key.
    pub public_key: [u8; 33],
}

/// A PQB seed owner. This type deliberately has no secret export operation.
pub struct PqbVault {
    seed: Zeroizing<[u8; 32]>,
}
impl core::fmt::Debug for PqbVault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PqbVault(***)")
    }
}
impl PqbVault {
    /// Import a 32-byte PQB seed. The caller must wipe its own source copy.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            seed: Zeroizing::new(*seed),
        }
    }

    /// Bind BIP85 child entropy to the fixed `PQB` real-puzzle profile and chain.
    /// One child must back at most one funded vault.
    pub fn from_child_entropy(entropy: &[u8; 32], network: PqbNetwork) -> Result<Self> {
        let tag = format!("pqb/vault-seed|hybrid|PQB|real|{}", network.name());
        Ok(Self {
            seed: crate::zeroizing_hmac::hmac::<Sha256, 32>(entropy, &[tag.as_bytes()])?,
        })
    }

    /// Restore from the 24 BIP85 child words displayed by a wallet. These are
    /// the child's entropy, not a new wallet root and not a BIP39 seed.
    pub fn from_child_mnemonic(words: &str, network: PqbNetwork) -> Result<Self> {
        Self::from_child_entropy(&*crate::mnemonic::child_entropy_32(words)?, network)
    }

    /// Derive BIP85 child `index` from a BIP39 wallet, keeping child entropy
    /// inside Krusty. Fails for an invalid mnemonic or an index >= 2^31.
    pub fn from_mnemonic(
        mnemonic: &str,
        passphrase: &str,
        index: u32,
        network: PqbNetwork,
    ) -> Result<Self> {
        if index >= 0x8000_0000 {
            return Err(invalid("BIP85 index must be below 2^31"));
        }
        let seed = Zeroizing::new(crate::mnemonic_to_seed(mnemonic, passphrase)?);
        let path = [83696968, 39, 0, 24, index].map(|i| i | 0x8000_0000);
        let key = crate::bitcoin::bip32::derive_private_key(seed.as_ref(), &path)?;
        let entropy =
            crate::zeroizing_hmac::hmac::<Sha512, 64>(b"bip-entropy-from-k", &[key.as_ref()])?;
        let mut child = Zeroizing::new([0; 32]);
        child.copy_from_slice(&entropy[..32]);
        Self::from_child_entropy(&child, network)
    }

    /// Derive public commitments, recovery points and the exact locking script.
    pub fn public_material(&self) -> Result<PqbPublicMaterial> {
        let commitments = std::array::from_fn(|i| {
            let preimage = key::take_secret_digest(&mut Sha256::digest(self.hors(i).as_ref()));
            require_wiped_hash::<Ripemd160>();
            Ripemd160::digest(preimage.as_ref()).into()
        });
        let secret_menus = self.menus()?;
        let menus = [
            secret_menus[0].public()?,
            secret_menus[1].public()?,
            secret_menus[2].public()?,
        ];
        let mut seen = std::collections::BTreeSet::new();
        if menus
            .iter()
            .flat_map(|m| &m.commitments)
            .any(|c| !seen.insert(*c))
        {
            return Err(invalid("menu commitments must be distinct across stages"));
        }
        let cosig_public_key = key::public_key(&self.cosig_key()?);
        let script = lock::build(&commitments, &menus, &cosig_public_key);
        Ok(PqbPublicMaterial {
            script_sha256: Sha256::digest(&script).into(),
            script,
            commitments,
            cosig_public_key,
            menus,
        })
    }

    /// Derive a deposit address without exposing the deposit private key.
    pub fn deposit(&self, network: PqbNetwork) -> Result<PqbDeposit> {
        let public_key = key::public_key(&self.deposit_key()?);
        let hash = hash160::Hash::hash(&public_key).to_byte_array();
        let address = crate::bitcoin::bech32::encode_segwit_v0(network.hrp(), &hash)?;
        let mut script_pubkey = vec![0, 20];
        script_pubkey.extend(hash);
        Ok(PqbDeposit {
            address,
            script_pubkey,
            public_key,
        })
    }

    /// Sign deposit P2WPKH PSBT inputs using the existing strict UTXO checks.
    /// Only SIGHASH_ALL is accepted; the deposit key never leaves Krusty.
    pub fn sign_deposit_psbt(&self, psbt: &str, inputs: &[u32]) -> Result<String> {
        let key = Zeroizing::new(self.deposit_key()?.to_bytes());
        crate::bitcoin::sign_pqb_deposit_psbt(key.as_ref(), psbt, inputs)
    }
}

fn invalid(message: impl Into<String>) -> KmsError {
    KmsError::TransactionError(format!("PQB: {}", message.into()))
}

// Feature removal must fail compilation rather than silently weaken wiping.
fn require_wiped_hash<D: zeroize::ZeroizeOnDrop>() {}
