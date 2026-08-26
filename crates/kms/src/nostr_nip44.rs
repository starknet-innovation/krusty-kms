//! Minimal NIP-44 v2 encryption used by NIP-59 application envelopes.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hkdf::Hkdf;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use k256::{PublicKey, SecretKey};
use krusty_kms_common::KmsError;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

const VERSION: u8 = 2;
const MIN_PAYLOAD_BYTES: usize = 99;
const MAX_PAYLOAD_BYTES: usize = 65_603;
const MAX_PLAINTEXT_BYTES: usize = 65_535;

fn conversation_key(
    private_key: &[u8; 32],
    peer_public_key: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, KmsError> {
    let secret = SecretKey::from_slice(private_key)
        .map_err(|error| KmsError::InvalidPrivateKey(error.to_string()))?;
    let mut compressed = [0u8; 33];
    compressed[0] = 2;
    compressed[1..].copy_from_slice(peer_public_key);
    let public = PublicKey::from_sec1_bytes(&compressed)
        .map_err(|error| KmsError::InvalidPublicKey(error.to_string()))?;
    let shared = secret.diffie_hellman(&public);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(b"nip44-v2"), shared.raw_secret_bytes());
    let mut result = Zeroizing::new([0u8; 32]);
    result.copy_from_slice(prk.as_slice());
    Ok(result)
}

fn message_keys(
    conversation_key: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<Zeroizing<[u8; 76]>, KmsError> {
    let hkdf = Hkdf::<Sha256>::from_prk(conversation_key)
        .map_err(|_| KmsError::CryptoError("Invalid NIP-44 conversation key".to_string()))?;
    let mut result = Zeroizing::new([0u8; 76]);
    hkdf.expand(nonce, result.as_mut())
        .map_err(|_| KmsError::CryptoError("Invalid NIP-44 message key".to_string()))?;
    Ok(result)
}

const fn padded_length(length: usize) -> usize {
    if length <= 32 {
        return 32;
    }
    let next_power = length.next_power_of_two();
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    chunk * (((length - 1) / chunk) + 1)
}

fn padded(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>, KmsError> {
    if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(KmsError::SerializationError(
            "NIP-44 plaintext must be 1-65535 bytes".to_string(),
        ));
    }
    let mut result = Zeroizing::new(vec![0u8; padded_length(plaintext.len()) + 2]);
    result[..2].copy_from_slice(&(plaintext.len() as u16).to_be_bytes());
    result[2..plaintext.len() + 2].copy_from_slice(plaintext);
    Ok(result)
}

fn encrypt_with_nonce(
    private_key: &[u8; 32],
    peer_public_key: &[u8; 32],
    plaintext: &str,
    nonce: &[u8; 32],
) -> Result<String, KmsError> {
    let conversation = conversation_key(private_key, peer_public_key)?;
    let keys = message_keys(&conversation, nonce)?;
    let mut ciphertext = padded(plaintext.as_bytes())?;
    let key: &[u8; 32] = keys[..32]
        .try_into()
        .map_err(|_| KmsError::CryptoError("Invalid NIP-44 cipher key".to_string()))?;
    let iv: &[u8; 12] = keys[32..44]
        .try_into()
        .map_err(|_| KmsError::CryptoError("Invalid NIP-44 cipher nonce".to_string()))?;
    let mut cipher = ChaCha20::new(key.into(), iv.into());
    cipher.apply_keystream(&mut ciphertext);
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&keys[44..])
        .map_err(|_| KmsError::CryptoError("Invalid NIP-44 HMAC key".to_string()))?;
    mac.update(nonce);
    mac.update(&ciphertext);
    let tag = mac.finalize().into_bytes();

    let mut payload = Vec::with_capacity(65 + ciphertext.len());
    payload.push(VERSION);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&tag);
    Ok(BASE64.encode(payload))
}

pub(crate) fn encrypt(
    private_key: &[u8; 32],
    peer_public_key: &[u8; 32],
    plaintext: &str,
) -> Result<String, KmsError> {
    let mut nonce = krusty_kms_crypto::try_random_bytes::<32>()
        .map_err(|error| KmsError::CryptoError(format!("NIP-44 entropy unavailable: {error}")))?;
    let result = encrypt_with_nonce(private_key, peer_public_key, plaintext, &nonce);
    nonce.zeroize();
    result
}

pub(crate) fn decrypt(
    private_key: &[u8; 32],
    peer_public_key: &[u8; 32],
    payload: &str,
) -> Result<String, KmsError> {
    if !(132..=87_472).contains(&payload.len()) || payload.starts_with('#') {
        return Err(KmsError::DeserializationError(
            "Invalid NIP-44 payload size".to_string(),
        ));
    }
    let decoded = BASE64
        .decode(payload)
        .map_err(|error| KmsError::DeserializationError(error.to_string()))?;
    if !(MIN_PAYLOAD_BYTES..=MAX_PAYLOAD_BYTES).contains(&decoded.len())
        || decoded.first() != Some(&VERSION)
    {
        return Err(KmsError::DeserializationError(
            "Invalid NIP-44 payload".to_string(),
        ));
    }
    let nonce: &[u8; 32] = decoded[1..33]
        .try_into()
        .map_err(|_| KmsError::DeserializationError("Invalid NIP-44 nonce".to_string()))?;
    let tag_at = decoded.len() - 32;
    let mut ciphertext = Zeroizing::new(decoded[33..tag_at].to_vec());
    let conversation = conversation_key(private_key, peer_public_key)?;
    let keys = message_keys(&conversation, nonce)?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&keys[44..])
        .map_err(|_| KmsError::CryptoError("Invalid NIP-44 HMAC key".to_string()))?;
    mac.update(nonce);
    mac.update(&ciphertext);
    mac.verify_slice(&decoded[tag_at..])
        .map_err(|_| KmsError::CryptoError("NIP-44 authentication failed".to_string()))?;

    let key: &[u8; 32] = keys[..32]
        .try_into()
        .map_err(|_| KmsError::CryptoError("Invalid NIP-44 cipher key".to_string()))?;
    let iv: &[u8; 12] = keys[32..44]
        .try_into()
        .map_err(|_| KmsError::CryptoError("Invalid NIP-44 cipher nonce".to_string()))?;
    let mut cipher = ChaCha20::new(key.into(), iv.into());
    cipher.apply_keystream(&mut ciphertext);
    let length = ciphertext
        .get(..2)
        .and_then(|bytes| <&[u8; 2]>::try_from(bytes).ok())
        .map(|bytes| u16::from_be_bytes(*bytes) as usize)
        .ok_or_else(|| KmsError::DeserializationError("Invalid NIP-44 padding".to_string()))?;
    if length == 0
        || length > MAX_PLAINTEXT_BYTES
        || ciphertext.len() != padded_length(length) + 2
        || ciphertext
            .get(length + 2..)
            .is_none_or(|padding| padding.iter().any(|byte| *byte != 0))
    {
        return Err(KmsError::DeserializationError(
            "Invalid NIP-44 padding".to_string(),
        ));
    }
    String::from_utf8(ciphertext[2..length + 2].to_vec())
        .map_err(|_| KmsError::DeserializationError("Invalid NIP-44 UTF-8".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes<const N: usize>(value: &str) -> [u8; N] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    #[test]
    fn matches_official_nip44_v2_vectors() {
        let first = bytes::<32>("0000000000000000000000000000000000000000000000000000000000000001");
        let second =
            bytes::<32>("0000000000000000000000000000000000000000000000000000000000000002");
        let peer = crate::nostr_public_key(&second).unwrap();
        let nonce = bytes::<32>("0000000000000000000000000000000000000000000000000000000000000001");
        let expected = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb";

        assert_eq!(
            hex::encode(conversation_key(&first, &peer).unwrap().as_ref()),
            "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d"
        );
        assert_eq!(
            encrypt_with_nonce(&first, &peer, "a", &nonce).unwrap(),
            expected
        );
        assert_eq!(
            decrypt(&second, &crate::nostr_public_key(&first).unwrap(), expected).unwrap(),
            "a"
        );

        let nonce = bytes::<32>("f00000000000000000000000000000f00000000000000000000000000000000f");
        let expected = "AvAAAAAAAAAAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAAPSKSK6is9ngkX2+cSq85Th16oRTISAOfhStnixqZziKMDvB0QQzgFZdjLTPicCJaV8nDITO+QfaQ61+KbWQIOO2Yj";
        assert_eq!(
            encrypt_with_nonce(
                &second,
                &crate::nostr_public_key(&first).unwrap(),
                "🍕🫃",
                &nonce
            )
            .unwrap(),
            expected
        );
        assert_eq!(decrypt(&first, &peer, expected).unwrap(), "🍕🫃");
    }
}
