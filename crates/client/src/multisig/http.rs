//! HTTP coordinator transport with SSRF protections.

mod ssrf;

use super::encoding::felt_to_hex;
use super::types::{
    validate_envelope_payload, validate_incoming_envelope, MultisigCoordinationEnvelope,
    MultisigCoordinator, MultisigTopic,
};
use async_trait::async_trait;
use krusty_kms_common::{KmsError, Result};
use ssrf::{build_ssrf_safe_client, validate_coordinator_url};
use url::Url;

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
    /// Prefer [`Self::from_url`] for untrusted URLs. This constructor uses the
    /// default reqwest redirect policy and does not validate resolved IPs.
    #[must_use]
    pub fn new_unchecked(mut base_url: Url) -> Self {
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }

        Self {
            base_url,
            client: reqwest::Client::new(),
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
        let client = build_ssrf_safe_client(&url)?;
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

        let envelopes = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|error| KmsError::MultisigError(error.to_string()))?
            .error_for_status()
            .map_err(|error| KmsError::MultisigError(error.to_string()))?
            .json::<Vec<MultisigCoordinationEnvelope>>()
            .await
            .map_err(|error| KmsError::MultisigError(error.to_string()))?;

        // Receive-side validation: the coordinator response is untrusted.
        for envelope in &envelopes {
            validate_incoming_envelope(topic, envelope)?;
        }
        Ok(envelopes)
    }
}
