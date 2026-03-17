//! Deterministic Stark-curve ECDSA signing utilities.
//!
//! Inputs:
//! - a Stark private key scalar
//! - a caller-supplied hash or felt message
//!
//! Outputs:
//! - Stark public key
//! - deterministic `(r, s)` signature values
//!
//! Invariants:
//! - signing is deterministic via RFC-6979 with cairo-compatible seed retry
//! - the helper signs the caller-supplied felt directly; it does not hash bytes
//! - out-of-range message values are rejected explicitly

use crate::KmsError;
use starknet_crypto::{get_public_key, rfc6979_generate_k, sign, Felt, SignError};

/// Deterministic Stark-curve signature output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarkSignature {
    pub public_key: Felt,
    pub r: Felt,
    pub s: Felt,
}

/// Derive the Stark public key corresponding to `private_key`.
pub fn stark_public_key(private_key: &Felt) -> Felt {
    get_public_key(private_key)
}

/// Sign a caller-supplied felt using deterministic RFC-6979 Stark ECDSA.
pub fn sign_stark_hash(private_key: &Felt, hash: &Felt) -> Result<StarkSignature, KmsError> {
    let mut seed = None;

    loop {
        let k = rfc6979_generate_k(hash, private_key, seed.as_ref());

        match sign(private_key, hash, &k) {
            Ok(signature) => {
                return Ok(StarkSignature {
                    public_key: get_public_key(private_key),
                    r: signature.r,
                    s: signature.s,
                });
            }
            Err(SignError::InvalidMessageHash) => {
                return Err(KmsError::CryptoError(
                    "stark signing message hash is out of range".to_string(),
                ));
            }
            Err(SignError::InvalidK) => {
                seed = Some(seed.unwrap_or(Felt::ZERO) + Felt::ONE);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use starknet_crypto::verify;

    #[test]
    fn sign_stark_hash_is_deterministic() {
        let private_key = Felt::from(42u64);
        let hash = Felt::from(0x1234u64);

        let first = sign_stark_hash(&private_key, &hash).unwrap();
        let second = sign_stark_hash(&private_key, &hash).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn sign_stark_hash_produces_verifiable_signature() {
        let private_key = Felt::from(42u64);
        let hash = Felt::from(0x1234u64);

        let signed = sign_stark_hash(&private_key, &hash).unwrap();
        let verified = verify(&signed.public_key, &hash, &signed.r, &signed.s).unwrap();

        assert!(verified);
    }

    #[test]
    fn stark_public_key_matches_signature_output() {
        let private_key = Felt::from(42u64);
        let hash = Felt::from(0x1234u64);

        let public_key = stark_public_key(&private_key);
        let signed = sign_stark_hash(&private_key, &hash).unwrap();

        assert_eq!(public_key, signed.public_key);
    }
}
