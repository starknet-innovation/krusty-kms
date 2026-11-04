//! NATS-backed coordinator transport.
//!
//! Inbound payloads are capped at [`MAX_COORDINATOR_PAYLOAD_BYTES`] before
//! they are parsed, matching the HTTP coordinator. This bounds the parse and
//! validation work only: `async-nats` enforces the server's `max_payload` on
//! publish but buffers whatever length a `MSG` frame declares on receive, so
//! a hostile server can still make the client allocate one oversized frame.
//! Bounding that allocation needs a receive-side cap upstream in `async-nats`.

use super::encoding::{address_subject_token, felt_subject_token};
use super::types::{
    validate_envelope_payload, validate_incoming_envelope, MultisigCoordinationEnvelope,
    MultisigCoordinator, MultisigMessageStream, MultisigTopic,
};
use super::MAX_COORDINATOR_PAYLOAD_BYTES;
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::StreamExt;
use krusty_kms_common::{KmsError, Result};

/// NATS-backed coordinator using standard pub/sub subjects.
///
/// NATS core pub/sub is live delivery. Use [`MultisigCoordinator::subscribe`]
/// before publishing when callers need to observe messages through this backend.
/// Use NATS JetStream at deployment time when durable retention is required.
#[derive(Clone)]
pub struct NatsMultisigCoordinator {
    client: async_nats::Client,
    subject_prefix: String,
}

impl NatsMultisigCoordinator {
    /// Connect to a NATS server using the default subject prefix.
    pub async fn connect(url: &str) -> Result<Self> {
        Self::connect_with_prefix(url, "krusty.multisig").await
    }

    /// Connect to a NATS server with a custom subject prefix.
    pub async fn connect_with_prefix(url: &str, subject_prefix: &str) -> Result<Self> {
        let client = async_nats::connect(url)
            .await
            .map_err(|error| KmsError::MultisigError(error.to_string()))?;
        Ok(Self::new(client, subject_prefix))
    }

    /// Build from an existing async NATS client.
    #[must_use]
    pub fn new(client: async_nats::Client, subject_prefix: &str) -> Self {
        Self {
            client,
            subject_prefix: subject_prefix.trim_end_matches('.').to_string(),
        }
    }

    /// Return the NATS subject for a multisig transaction topic.
    #[must_use]
    pub fn subject(&self, topic: &MultisigTopic) -> String {
        Self::subject_for(&self.subject_prefix, topic)
    }

    /// Return the NATS subject for a prefix and transaction topic.
    ///
    /// The chain id is a subject token so one shared NATS deployment can serve
    /// multiple networks without cross-chain message leakage.
    #[must_use]
    pub fn subject_for(subject_prefix: &str, topic: &MultisigTopic) -> String {
        format!(
            "{}.{}.{}.{}",
            subject_prefix.trim_end_matches('.'),
            topic.chain_id.name(),
            address_subject_token(topic.multisig),
            felt_subject_token(topic.transaction_id)
        )
    }
}

#[async_trait]
impl MultisigCoordinator for NatsMultisigCoordinator {
    async fn publish(&self, envelope: MultisigCoordinationEnvelope) -> Result<()> {
        validate_envelope_payload(&envelope)?;

        let subject = self.subject(&envelope.topic());
        let payload = serde_json::to_vec(&envelope)
            .map_err(|error| KmsError::MultisigError(error.to_string()))?;
        self.client
            .publish(subject, Bytes::from(payload))
            .await
            .map_err(|error| KmsError::MultisigError(error.to_string()))?;
        self.client
            .flush()
            .await
            .map_err(|error| KmsError::MultisigError(error.to_string()))?;
        Ok(())
    }

    async fn subscribe(&self, topic: &MultisigTopic) -> Result<MultisigMessageStream> {
        let subject = self.subject(topic);
        let subscriber = self
            .client
            .subscribe(subject)
            .await
            .map_err(|error| KmsError::MultisigError(error.to_string()))?;

        let topic = topic.clone();
        Ok(Box::pin(subscriber.map(move |message| {
            decode_subscribed_payload(&topic, &message.payload)
        })))
    }
}

/// Parse and validate one inbound payload for `topic`.
///
/// The coordinator is untrusted on the receive path: the size cap runs before
/// any parsing, and the parsed envelope is rejected on a misrouted topic, an
/// unsupported schema version, or a proposal whose id does not recompute.
fn decode_subscribed_payload(
    topic: &MultisigTopic,
    payload: &[u8],
) -> Result<MultisigCoordinationEnvelope> {
    if payload.len() > MAX_COORDINATOR_PAYLOAD_BYTES {
        return Err(KmsError::MultisigError(format!(
            "coordinator message exceeds the {MAX_COORDINATOR_PAYLOAD_BYTES} byte limit"
        )));
    }
    let parsed = serde_json::from_slice::<MultisigCoordinationEnvelope>(payload)
        .map_err(|error| KmsError::MultisigError(error.to_string()))?;
    validate_incoming_envelope(topic, &parsed)?;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use krusty_kms_common::{Address, ChainId};
    use starknet_types_core::felt::Felt;

    fn topic() -> MultisigTopic {
        MultisigTopic {
            multisig: Address::from(Felt::from(0x401u64)),
            chain_id: ChainId::Sepolia,
            transaction_id: Felt::from(0x55u64),
        }
    }

    /// Audit 2026-11-04, M-3: an oversized payload is refused by its length
    /// alone, before any byte of it is parsed.
    #[test]
    fn oversized_payload_is_rejected_before_parsing() {
        // Starts like JSON, so a parser that ran would report a JSON error.
        let mut payload = vec![b' '; MAX_COORDINATOR_PAYLOAD_BYTES + 1];
        payload[0] = b'{';
        let err = decode_subscribed_payload(&topic(), &payload).expect_err("must be rejected");
        assert!(
            matches!(err, KmsError::MultisigError(ref m) if m.contains("byte limit")),
            "got {err:?}"
        );
    }

    /// A payload at the cap reaches the parser, so the bound is exact and
    /// the HTTP coordinator's limit still fits through this transport.
    #[test]
    fn payload_at_the_cap_reaches_the_parser() {
        let payload = vec![b' '; MAX_COORDINATOR_PAYLOAD_BYTES];
        let err = decode_subscribed_payload(&topic(), &payload).expect_err("blank JSON");
        assert!(
            matches!(err, KmsError::MultisigError(ref m) if !m.contains("byte limit")),
            "got {err:?}"
        );
    }
}
