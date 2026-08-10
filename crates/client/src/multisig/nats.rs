//! NATS-backed coordinator transport.

use super::encoding::{address_subject_token, felt_subject_token};
use super::types::{
    validate_incoming_message, MultisigCoordinationMessage, MultisigCoordinator,
    MultisigMessageStream, MultisigTopic,
};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::StreamExt;
use krusty_kms_common::{KmsError, Result};

/// NATS-backed trusted coordinator using standard pub/sub subjects.
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
    async fn publish(&self, message: MultisigCoordinationMessage) -> Result<()> {
        if let MultisigCoordinationMessage::Proposal(proposal) = &message {
            proposal.validate_transaction_id()?;
        }

        let subject = self.subject(&message.topic());
        let payload = serde_json::to_vec(&message)
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
            let parsed = serde_json::from_slice::<MultisigCoordinationMessage>(&message.payload)
                .map_err(|error| KmsError::MultisigError(error.to_string()))?;
            // The coordinator is untrusted on the receive path: reject
            // misrouted topics and proposals whose id does not recompute.
            validate_incoming_message(&topic, &parsed)?;
            Ok(parsed)
        })))
    }
}
