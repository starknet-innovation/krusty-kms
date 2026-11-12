//! Generic Nostr event primitives: canonical ids, signing and verification.

use crate::nostr_signing::{nostr_public_key, sign_nostr_event_id};
use k256::schnorr::signature::hazmat::PrehashVerifier;
use k256::schnorr::{Signature, VerifyingKey};
use krusty_kms_common::KmsError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UnsignedEvent {
    pub(super) id: String,
    pub(super) pubkey: String,
    pub(super) created_at: u64,
    pub(super) kind: u16,
    pub(super) tags: Vec<Vec<String>>,
    pub(super) content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SignedEvent {
    pub(super) id: String,
    pub(super) pubkey: String,
    pub(super) created_at: u64,
    pub(super) kind: u16,
    pub(super) tags: Vec<Vec<String>>,
    pub(super) content: String,
    pub(super) sig: String,
}

pub(super) fn decode_hex<const N: usize>(value: &str, name: &str) -> Result<[u8; N], KmsError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(KmsError::DeserializationError(format!(
            "Invalid Nostr {name}"
        )));
    }
    hex::decode(value)?
        .try_into()
        .map_err(|_| KmsError::DeserializationError(format!("Invalid Nostr {name}")))
}

pub(super) fn event_id(
    public_key: &str,
    created_at: u64,
    kind: u16,
    tags: &[Vec<String>],
    content: &str,
) -> Result<[u8; 32], KmsError> {
    let canonical = serde_json::to_vec(&(0, public_key, created_at, kind, tags, content))?;
    Ok(Sha256::digest(canonical).into())
}

pub(super) fn unsigned_event(
    public_key: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
) -> Result<UnsignedEvent, KmsError> {
    let id = event_id(&public_key, created_at, kind, &tags, &content)?;
    Ok(UnsignedEvent {
        id: hex::encode(id),
        pubkey: public_key,
        created_at,
        kind,
        tags,
        content,
    })
}

pub(super) fn signed_event(
    private_key: &[u8; 32],
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
) -> Result<SignedEvent, KmsError> {
    let public_key = hex::encode(nostr_public_key(private_key)?);
    let id = event_id(&public_key, created_at, kind, &tags, &content)?;
    let signature = sign_nostr_event_id(private_key, &id)?;
    Ok(SignedEvent {
        id: hex::encode(id),
        pubkey: public_key,
        created_at,
        kind,
        tags,
        content,
        sig: hex::encode(signature.signature),
    })
}

pub(super) fn verify_event(event: &SignedEvent) -> Result<(), KmsError> {
    let expected = event_id(
        &event.pubkey,
        event.created_at,
        event.kind,
        &event.tags,
        &event.content,
    )?;
    if decode_hex::<32>(&event.id, "event id")? != expected {
        return Err(KmsError::CryptoError(
            "Nostr event id does not match its contents".to_string(),
        ));
    }
    let public_key = decode_hex::<32>(&event.pubkey, "public key")?;
    let signature_bytes = decode_hex::<64>(&event.sig, "signature")?;
    let verifying_key = VerifyingKey::from_slice(&public_key)
        .map_err(|error| KmsError::InvalidPublicKey(error.to_string()))?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|error| KmsError::CryptoError(error.to_string()))?;
    verifying_key
        .verify_prehash(&expected, &signature)
        .map_err(|_| KmsError::CryptoError("Nostr event signature is invalid".to_string()))
}
