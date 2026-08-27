//! NIP-59 transport for bounded, non-chat application data.

use crate::nostr_nip44;
use crate::nostr_signing::{nostr_public_key, sign_nostr_event_id};
use k256::schnorr::signature::hazmat::PrehashVerifier;
use k256::schnorr::{Signature, VerifyingKey};
use krusty_kms_common::KmsError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const APPLICATION_DATA_KIND: u16 = 30_078;
const SEAL_KIND: u16 = 13;
const GIFT_WRAP_KIND: u16 = 1_059;
const MAX_CONTENT_BYTES: usize = 32_768;
const MAX_EVENT_JSON_BYTES: usize = 131_070;
const MAX_IDENTIFIER_BYTES: usize = 128;
const TWO_DAYS_SECONDS: u64 = 2 * 24 * 60 * 60;

/// Authenticated application data recovered from a NIP-59 gift wrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NostrApplicationData {
    pub content: String,
    pub identifier: String,
    pub sender_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsignedEvent {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedEvent {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

fn valid_identifier(identifier: &str) -> bool {
    !identifier.is_empty()
        && identifier.len() <= MAX_IDENTIFIER_BYTES
        && identifier.bytes().all(|byte| (b' '..=b'~').contains(&byte))
}

fn validate_content(content: &str) -> Result<(), KmsError> {
    if content.is_empty() || content.len() > MAX_CONTENT_BYTES {
        return Err(KmsError::SerializationError(
            "Nostr application data must be 1-32768 UTF-8 bytes".to_string(),
        ));
    }
    Ok(())
}

fn validate_nested_plaintext(value: &str) -> Result<(), KmsError> {
    if !nostr_nip44::valid_plaintext(value.as_bytes()) {
        return Err(KmsError::SerializationError(
            "Nostr application data exceeds the nested envelope limit".to_string(),
        ));
    }
    Ok(())
}

fn decode_hex<const N: usize>(value: &str, name: &str) -> Result<[u8; N], KmsError> {
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

fn event_id(
    public_key: &str,
    created_at: u64,
    kind: u16,
    tags: &[Vec<String>],
    content: &str,
) -> Result<[u8; 32], KmsError> {
    let canonical = serde_json::to_vec(&(0, public_key, created_at, kind, tags, content))?;
    Ok(Sha256::digest(canonical).into())
}

fn unsigned_event(
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

fn signed_event(
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

fn verify_event(event: &SignedEvent) -> Result<(), KmsError> {
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

fn now_seconds() -> Result<u64, KmsError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| KmsError::CryptoError("System clock is unavailable".to_string()))
}

fn randomized_past_timestamp(now: u64) -> Result<u64, KmsError> {
    let offset =
        u64::from_be_bytes(krusty_kms_crypto::try_random_bytes::<8>().map_err(|error| {
            KmsError::CryptoError(format!("Nostr entropy unavailable: {error}"))
        })?) % (TWO_DAYS_SECONDS + 1);
    Ok(now.saturating_sub(offset))
}

fn ephemeral_private_key() -> Result<Zeroizing<[u8; 32]>, KmsError> {
    for _ in 0..8 {
        let mut candidate = Zeroizing::new([0u8; 32]);
        krusty_kms_crypto::try_fill_random_bytes(candidate.as_mut()).map_err(|error| {
            KmsError::CryptoError(format!("Nostr entropy unavailable: {error}"))
        })?;
        if nostr_public_key(&candidate).is_ok() {
            return Ok(candidate);
        }
    }
    Err(KmsError::CryptoError(
        "Could not generate a valid Nostr key".to_string(),
    ))
}

/// Wraps one bounded application-data rumor for one Nostr recipient.
pub fn wrap_nostr_application_data(
    private_key: &[u8; 32],
    recipient_public_key: &str,
    identifier: &str,
    content: &str,
) -> Result<String, KmsError> {
    wrap_nostr_application_data_at(
        private_key,
        recipient_public_key,
        identifier,
        content,
        now_seconds()?,
    )
}

/// Wraps application data using a caller-supplied current Unix timestamp.
///
/// This is the WASM-safe clock boundary. The seal and gift-wrap timestamps are
/// still independently randomized across NIP-59's two-day window.
pub fn wrap_nostr_application_data_at(
    private_key: &[u8; 32],
    recipient_public_key: &str,
    identifier: &str,
    content: &str,
    now: u64,
) -> Result<String, KmsError> {
    validate_content(content)?;
    if !valid_identifier(identifier) {
        return Err(KmsError::SerializationError(
            "Invalid Nostr application identifier".to_string(),
        ));
    }
    let recipient = decode_hex::<32>(recipient_public_key, "recipient public key")?;
    let sender_public_key = hex::encode(nostr_public_key(private_key)?);
    let rumor = unsigned_event(
        sender_public_key,
        now,
        APPLICATION_DATA_KIND,
        vec![vec!["d".to_string(), identifier.to_string()]],
        content.to_string(),
    )?;
    let rumor_json = serde_json::to_string(&rumor)?;
    validate_nested_plaintext(&rumor_json)?;
    let seal_content = nostr_nip44::encrypt(private_key, &recipient, &rumor_json)?;
    let seal = signed_event(
        private_key,
        randomized_past_timestamp(now)?,
        SEAL_KIND,
        Vec::new(),
        seal_content,
    )?;
    let seal_json = serde_json::to_string(&seal)?;
    validate_nested_plaintext(&seal_json)?;
    let ephemeral = ephemeral_private_key()?;
    let wrap_content = nostr_nip44::encrypt(&ephemeral, &recipient, &seal_json)?;
    let wrap = signed_event(
        &ephemeral,
        randomized_past_timestamp(now)?,
        GIFT_WRAP_KIND,
        vec![vec!["p".to_string(), recipient_public_key.to_string()]],
        wrap_content,
    )?;
    serde_json::to_string(&wrap).map_err(Into::into)
}

/// Opens and authenticates one NIP-59 application-data gift wrap.
pub fn open_nostr_application_data(
    private_key: &[u8; 32],
    event_json: &str,
) -> Result<NostrApplicationData, KmsError> {
    if event_json.is_empty() || event_json.len() > MAX_EVENT_JSON_BYTES {
        return Err(KmsError::DeserializationError(
            "Invalid Nostr gift-wrap size".to_string(),
        ));
    }
    let wrap: SignedEvent = serde_json::from_str(event_json)?;
    verify_event(&wrap)?;
    let recipient_public_key = hex::encode(nostr_public_key(private_key)?);
    if wrap.kind != GIFT_WRAP_KIND || wrap.tags != vec![vec!["p".to_string(), recipient_public_key]]
    {
        return Err(KmsError::DeserializationError(
            "Invalid Nostr gift wrap".to_string(),
        ));
    }

    let wrap_public_key = decode_hex::<32>(&wrap.pubkey, "gift-wrap public key")?;
    let seal_json = nostr_nip44::decrypt(private_key, &wrap_public_key, &wrap.content)?;
    let seal: SignedEvent = serde_json::from_str(&seal_json)?;
    verify_event(&seal)?;
    if seal.kind != SEAL_KIND || !seal.tags.is_empty() {
        return Err(KmsError::DeserializationError(
            "Invalid Nostr seal".to_string(),
        ));
    }

    let sender_public_key = decode_hex::<32>(&seal.pubkey, "sender public key")?;
    let rumor_json = nostr_nip44::decrypt(private_key, &sender_public_key, &seal.content)?;
    let rumor: UnsignedEvent = serde_json::from_str(&rumor_json)?;
    let expected_id = event_id(
        &rumor.pubkey,
        rumor.created_at,
        rumor.kind,
        &rumor.tags,
        &rumor.content,
    )?;
    if rumor.id != hex::encode(expected_id)
        || rumor.pubkey != seal.pubkey
        || rumor.kind != APPLICATION_DATA_KIND
        || rumor.tags.len() != 1
        || rumor.tags[0].len() != 2
        || rumor.tags[0][0] != "d"
        || !valid_identifier(&rumor.tags[0][1])
    {
        return Err(KmsError::DeserializationError(
            "Invalid Nostr application rumor".to_string(),
        ));
    }
    validate_content(&rumor.content)?;
    Ok(NostrApplicationData {
        content: rumor.content,
        identifier: rumor.tags[0][1].clone(),
        sender_public_key: rumor.pubkey,
    })
}

#[cfg(test)]
mod tests;
