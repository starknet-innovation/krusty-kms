//! Deterministic Nostr event signing using BIP-340 Schnorr over secp256k1.
//!
//! Inputs:
//! - a 32-byte secp256k1 private key derived for the Nostr domain
//! - a 32-byte event id digest
//!
//! Outputs:
//! - x-only public key bytes
//! - a 64-byte BIP-340 signature
//!
//! Invariants:
//! - signing is deterministic (`aux_rand = 0`) so repeated calls are stable
//! - the returned public key is the x-only BIP-340 verifying key
//! - invalid secret scalars are rejected before signing

use crate::KmsError;
use k256::schnorr::signature::Signer;
use k256::schnorr::SigningKey;

/// Deterministic BIP-340 signing output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrSignature {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

/// Backwards-compatible alias for the event-id-specific naming used initially.
pub type NostrEventSignature = NostrSignature;

/// Derive the x-only Nostr public key for a secp256k1 private key.
pub fn nostr_public_key(private_key: &[u8; 32]) -> Result<[u8; 32], KmsError> {
    let signing_key = parse_signing_key(private_key)?;
    Ok(signing_key.verifying_key().to_bytes().into())
}

/// Sign a 32-byte Nostr event id using deterministic BIP-340 Schnorr.
pub fn sign_nostr_event_id(
    private_key: &[u8; 32],
    event_id: &[u8; 32],
) -> Result<NostrSignature, KmsError> {
    sign_nostr_event_id_with_aux_rand(private_key, event_id, &[0u8; 32])
}

/// Sign a raw message using the standard BIP-340 byte-message API.
///
/// This does not promise Nostr event semantics. Callers that already have a
/// canonical 32-byte event id should use [`sign_nostr_event_id`] instead.
pub fn sign_nostr_message(
    private_key: &[u8; 32],
    message: &[u8],
) -> Result<NostrSignature, KmsError> {
    let signing_key = parse_signing_key(private_key)?;
    let signature: k256::schnorr::Signature = signing_key.sign(message);

    Ok(NostrSignature {
        public_key: signing_key.verifying_key().to_bytes().into(),
        signature: signature.to_bytes(),
    })
}

fn parse_signing_key(private_key: &[u8; 32]) -> Result<SigningKey, KmsError> {
    SigningKey::from_bytes(private_key)
        .map_err(|error| KmsError::InvalidPrivateKey(format!("Invalid secp256k1 key: {error}")))
}

fn sign_nostr_event_id_with_aux_rand(
    private_key: &[u8; 32],
    event_id: &[u8; 32],
    aux_rand: &[u8; 32],
) -> Result<NostrSignature, KmsError> {
    let signing_key = parse_signing_key(private_key)?;
    let signature = signing_key
        .sign_prehash_with_aux_rand(event_id, aux_rand)
        .map_err(|error| KmsError::CryptoError(format!("nostr signing failed: {error}")))?;

    Ok(NostrSignature {
        public_key: signing_key.verifying_key().to_bytes().into(),
        signature: signature.to_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::decode;
    use k256::schnorr::{
        signature::{hazmat::PrehashVerifier, Verifier},
        Signature, VerifyingKey,
    };

    fn decode_array<const N: usize>(hex_value: &str) -> [u8; N] {
        let bytes = decode(hex_value).unwrap();
        bytes.try_into().unwrap()
    }

    #[test]
    fn sign_nostr_event_id_is_deterministic() {
        let private_key =
            decode_array::<32>("b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe4");
        let event_id =
            decode_array::<32>("243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89");

        let first = sign_nostr_event_id(&private_key, &event_id).unwrap();
        let second = sign_nostr_event_id(&private_key, &event_id).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn sign_nostr_event_id_produces_verifiable_signature() {
        let private_key =
            decode_array::<32>("1dce8d2ec6184cca9433f8f7b2702d9014936627ce0f50926f471e52946d0f4c");
        let event_id =
            decode_array::<32>("6c3fd336b5457a0f2b74959f177a5c5e7f9ab75cdb4ab7a3ec7aaf1e2a3d2b13");

        let signed = sign_nostr_event_id(&private_key, &event_id).unwrap();
        let verifying_key = VerifyingKey::from_bytes(&signed.public_key).unwrap();
        let signature = Signature::try_from(signed.signature.as_slice()).unwrap();

        verifying_key.verify_prehash(&event_id, &signature).unwrap();
    }

    #[test]
    fn nostr_public_key_matches_signature_output() {
        let private_key =
            decode_array::<32>("1dce8d2ec6184cca9433f8f7b2702d9014936627ce0f50926f471e52946d0f4c");
        let event_id =
            decode_array::<32>("6c3fd336b5457a0f2b74959f177a5c5e7f9ab75cdb4ab7a3ec7aaf1e2a3d2b13");

        let public_key = nostr_public_key(&private_key).unwrap();
        let signed = sign_nostr_event_id(&private_key, &event_id).unwrap();

        assert_eq!(public_key, signed.public_key);
    }

    #[test]
    fn invalid_nostr_private_key_is_rejected() {
        let error = sign_nostr_event_id(&[0u8; 32], &[1u8; 32]).unwrap_err();

        assert!(matches!(error, KmsError::InvalidPrivateKey(_)));
    }

    #[test]
    fn sign_nostr_message_produces_verifiable_signature() {
        let private_key =
            decode_array::<32>("1dce8d2ec6184cca9433f8f7b2702d9014936627ce0f50926f471e52946d0f4c");
        let message = b"hello nostr raw message";

        let signed = sign_nostr_message(&private_key, message).unwrap();
        let verifying_key = VerifyingKey::from_bytes(&signed.public_key).unwrap();
        let signature = Signature::try_from(signed.signature.as_slice()).unwrap();

        verifying_key.verify(message, &signature).unwrap();
    }

    #[test]
    fn signing_matches_bip340_reference_vector_when_aux_rand_is_specified() {
        let private_key =
            decode_array::<32>("0000000000000000000000000000000000000000000000000000000000000003");
        let event_id =
            decode_array::<32>("0000000000000000000000000000000000000000000000000000000000000000");
        let aux_rand =
            decode_array::<32>("0000000000000000000000000000000000000000000000000000000000000000");

        let signed = sign_nostr_event_id_with_aux_rand(&private_key, &event_id, &aux_rand).unwrap();

        assert_eq!(
            hex::encode(signed.public_key),
            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
        );
        assert_eq!(
            hex::encode(signed.signature),
            "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0"
        );
    }
}
