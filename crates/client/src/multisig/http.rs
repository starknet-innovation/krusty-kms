//! HTTP coordinator transport with SSRF protections.

mod ssrf;

use super::encoding::felt_to_hex;
use super::types::{
    validate_envelope_payload, validate_incoming_envelope, MultisigCoordinationEnvelope,
    MultisigCoordinator, MultisigTopic,
};
#[cfg(test)]
use super::types::{MultisigCoordinationMessage, MultisigSignerNotice};
use async_trait::async_trait;
use krusty_kms_common::{KmsError, Result};
use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use ssrf::{build_ssrf_safe_client, validate_coordinator_url};
use std::fmt;
use std::time::Duration;
use url::Url;

const COORDINATOR_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const COORDINATOR_READ_TIMEOUT: Duration = Duration::from_secs(15);
const COORDINATOR_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_COORDINATOR_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_COORDINATOR_ENVELOPES: usize = 1_024;

/// HTTP implementation of the coordinator protocol.
///
/// Expected server API:
///
/// - `POST /v1/multisig/messages` with a [`MultisigCoordinationEnvelope`] JSON body.
/// - `GET /v1/multisig/messages?multisig=<addr>&transaction_id=<id>` returning
///   `Vec<MultisigCoordinationEnvelope>`.
#[derive(Clone)]
pub struct HttpMultisigCoordinator {
    base_url: Url,
    client: reqwest::Client,
}

impl HttpMultisigCoordinator {
    /// Create a coordinator from a parsed base URL **without** SSRF checks.
    ///
    /// Prefer [`Self::from_url`] for untrusted URLs. This constructor does not
    /// validate resolved IPs, proxies, or redirect targets, but it does apply
    /// the same connect, read-idle, and total request deadlines as the checked
    /// constructor.
    #[must_use]
    pub fn new_unchecked(mut base_url: Url) -> Self {
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }

        Self {
            base_url,
            client: reqwest::Client::builder()
                .connect_timeout(COORDINATOR_CONNECT_TIMEOUT)
                .read_timeout(COORDINATOR_READ_TIMEOUT)
                .timeout(COORDINATOR_REQUEST_TIMEOUT)
                .build()
                .expect("fixed coordinator HTTP client settings must be valid"),
        }
    }

    /// Parse a coordinator base URL with SSRF protections.
    ///
    /// Only `http`/`https` are accepted. Hostnames are DNS-resolved and every
    /// address must be publicly routable (no loopback, RFC1918, ULA, link-local,
    /// CGNAT, metadata, etc.). The HTTP client uses a validating DNS resolver so
    /// every connection-time lookup (and redirect hop) is re-checked, closing the
    /// DNS-rebinding gap between preflight validation and `send()`.
    /// Use [`Self::from_url_unchecked`] in tests or when the caller has already
    /// validated the URL against a local allowlist.
    pub fn from_url(base_url: &str) -> Result<Self> {
        let mut url =
            Url::parse(base_url).map_err(|error| KmsError::MultisigError(error.to_string()))?;
        validate_coordinator_url(&url)?;
        if !url.path().ends_with('/') {
            let path = format!("{}/", url.path());
            url.set_path(&path);
        }
        let client = build_ssrf_safe_client(
            &url,
            COORDINATOR_CONNECT_TIMEOUT,
            COORDINATOR_READ_TIMEOUT,
            COORDINATOR_REQUEST_TIMEOUT,
        )?;
        Ok(Self {
            base_url: url,
            client,
        })
    }

    /// Parse a coordinator URL without SSRF host/scheme checks.
    ///
    /// Intended for tests and explicitly trusted local tooling.
    pub fn from_url_unchecked(base_url: &str) -> Result<Self> {
        let url =
            Url::parse(base_url).map_err(|error| KmsError::MultisigError(error.to_string()))?;
        match url.scheme() {
            "http" | "https" => Ok(Self::new_unchecked(url)),
            other => Err(KmsError::MultisigError(format!(
                "unsupported coordinator URL scheme '{other}' (only http/https)"
            ))),
        }
    }

    pub(super) fn messages_url(&self) -> Result<Url> {
        self.base_url
            .join("v1/multisig/messages")
            .map_err(|error| KmsError::MultisigError(error.to_string()))
    }
}

fn append_response_chunk(body: &mut Vec<u8>, chunk: &[u8]) -> Result<()> {
    if chunk.len() > MAX_COORDINATOR_RESPONSE_BYTES.saturating_sub(body.len()) {
        return Err(KmsError::MultisigError(format!(
            "coordinator response exceeds the {MAX_COORDINATOR_RESPONSE_BYTES} byte limit"
        )));
    }
    body.extend_from_slice(chunk);
    Ok(())
}

async fn read_bounded_response(mut response: reqwest::Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_COORDINATOR_RESPONSE_BYTES as u64)
    {
        return Err(KmsError::MultisigError(format!(
            "coordinator response exceeds the {MAX_COORDINATOR_RESPONSE_BYTES} byte limit"
        )));
    }

    let capacity = response
        .content_length()
        .unwrap_or(0)
        .min(MAX_COORDINATOR_RESPONSE_BYTES as u64) as usize;
    let mut body = Vec::with_capacity(capacity);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| KmsError::MultisigError(error.to_string()))?
    {
        append_response_chunk(&mut body, &chunk)?;
    }
    Ok(body)
}

struct BoundedEnvelopes(Vec<MultisigCoordinationEnvelope>);

impl<'de> Deserialize<'de> for BoundedEnvelopes {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedEnvelopesVisitor;

        impl<'de> Visitor<'de> for BoundedEnvelopesVisitor {
            type Value = BoundedEnvelopes;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "an array of at most {MAX_COORDINATOR_ENVELOPES} coordinator envelopes"
                )
            }

            fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut envelopes = Vec::with_capacity(
                    sequence
                        .size_hint()
                        .unwrap_or(0)
                        .min(MAX_COORDINATOR_ENVELOPES),
                );
                while let Some(envelope) = sequence.next_element()? {
                    if envelopes.len() == MAX_COORDINATOR_ENVELOPES {
                        return Err(A::Error::custom(format!(
                            "coordinator response exceeds the {MAX_COORDINATOR_ENVELOPES} envelope limit"
                        )));
                    }
                    envelopes.push(envelope);
                }
                Ok(BoundedEnvelopes(envelopes))
            }
        }

        deserializer.deserialize_seq(BoundedEnvelopesVisitor)
    }
}

fn decode_envelopes(body: &[u8]) -> Result<Vec<MultisigCoordinationEnvelope>> {
    serde_json::from_slice::<BoundedEnvelopes>(body)
        .map(|bounded| bounded.0)
        .map_err(|error| KmsError::MultisigError(error.to_string()))
}

#[async_trait]
impl MultisigCoordinator for HttpMultisigCoordinator {
    async fn publish(&self, envelope: MultisigCoordinationEnvelope) -> Result<()> {
        validate_envelope_payload(&envelope)?;

        self.client
            .post(self.messages_url()?)
            .json(&envelope)
            .send()
            .await
            .map_err(|error| KmsError::MultisigError(error.to_string()))?
            .error_for_status()
            .map_err(|error| KmsError::MultisigError(error.to_string()))?;
        Ok(())
    }

    async fn messages(&self, topic: &MultisigTopic) -> Result<Vec<MultisigCoordinationEnvelope>> {
        let mut url = self.messages_url()?;
        url.query_pairs_mut()
            .append_pair("multisig", &topic.multisig.to_hex())
            .append_pair("chain_id", topic.chain_id.name())
            .append_pair("transaction_id", &felt_to_hex(topic.transaction_id));

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|error| KmsError::MultisigError(error.to_string()))?
            .error_for_status()
            .map_err(|error| KmsError::MultisigError(error.to_string()))?;
        let body = read_bounded_response(response).await?;
        let envelopes = decode_envelopes(&body)?;

        // Receive-side validation: the coordinator response is untrusted.
        for envelope in &envelopes {
            validate_incoming_envelope(topic, envelope)?;
        }
        Ok(envelopes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_body_limit_is_enforced_before_extending() {
        let mut body = vec![0; MAX_COORDINATOR_RESPONSE_BYTES];
        assert!(append_response_chunk(&mut body, &[1]).is_err());
        assert_eq!(body.len(), MAX_COORDINATOR_RESPONSE_BYTES);
    }

    #[test]
    fn envelope_count_limit_is_enforced_during_typed_decoding() {
        let envelope = MultisigCoordinationEnvelope::Unsigned(
            MultisigCoordinationMessage::Confirmation(MultisigSignerNotice::new(
                krusty_kms_common::Address::from(starknet_types_core::felt::Felt::ONE),
                krusty_kms_common::ChainId::Sepolia,
                starknet_types_core::felt::Felt::TWO,
                krusty_kms_common::Address::from(starknet_types_core::felt::Felt::THREE),
            )),
        );
        let encoded = serde_json::to_string(&envelope).unwrap();
        let body = format!(
            "[{}]",
            vec![encoded; MAX_COORDINATOR_ENVELOPES + 1].join(",")
        );
        let error = decode_envelopes(body.as_bytes()).unwrap_err();
        assert!(error.to_string().contains("envelope limit"));
    }

    #[test]
    fn empty_coordinator_response_is_valid() {
        assert!(decode_envelopes(b"[]").unwrap().is_empty());
    }
}
