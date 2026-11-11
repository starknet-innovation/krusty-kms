//! NIP-59 transport for bounded, non-chat application data.

use crate::nostr_nip44;
use crate::nostr_signing::nostr_public_key;
use event::{
    decode_hex, event_id, signed_event, unsigned_event, verify_event, SignedEvent, UnsignedEvent,
};
use krusty_kms_common::KmsError;
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

/// [`NostrApplicationData`] plus the verified ids and timestamp callers need
/// to reject replays. Opening is stateless: the same wrap opens every time.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OpenedNostrApplicationData {
    pub data: NostrApplicationData,
    /// Verified gift-wrap event id. Deduplicating on it drops relay replays.
    pub wrap_id: String,
    /// Verified rumor event id. Unchanged when the same seal is re-wrapped,
    /// so deduplicating on it also drops sender or recipient re-wraps.
    pub rumor_id: String,
    /// Rumor `created_at` (NIP-59's canonical time). Authenticated as the
    /// sender's claim, not as a trusted clock.
    pub created_at: u64,
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
///
/// Content is limited to 32,768 bytes, and its JSON-escaped form must also
/// fit the nested NIP-44 envelope: at most 40,614 to 40,742 escaped bytes,
/// depending on the identifier length. Quotes, backslashes and control
/// characters expand when escaped.
///
/// Reads the system clock, which panics on `wasm32-unknown-unknown`; use
/// [`wrap_nostr_application_data_at`] there.
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
///
/// Opening is stateless, so replay protection is the caller's job; use
/// [`open_nostr_application_data_with_metadata`] to get the ids and timestamp
/// for it. Only Krusty's exact wrap shape is accepted: a single `["p", recipient]`
/// tag, kind 1059, and no relay hints, `expiration` or proof-of-work tags.
pub fn open_nostr_application_data(
    private_key: &[u8; 32],
    event_json: &str,
) -> Result<NostrApplicationData, KmsError> {
    open_nostr_application_data_with_metadata(private_key, event_json).map(|opened| opened.data)
}

/// Like [`open_nostr_application_data`], also returning the verified wrap id,
/// rumor id and rumor `created_at` for replay and freshness checks.
pub fn open_nostr_application_data_with_metadata(
    private_key: &[u8; 32],
    event_json: &str,
) -> Result<OpenedNostrApplicationData, KmsError> {
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
    Ok(OpenedNostrApplicationData {
        data: NostrApplicationData {
            content: rumor.content,
            identifier: rumor.tags[0][1].clone(),
            sender_public_key: rumor.pubkey,
        },
        wrap_id: wrap.id,
        rumor_id: rumor.id,
        created_at: rumor.created_at,
    })
}

mod event;
#[cfg(test)]
mod tests;
