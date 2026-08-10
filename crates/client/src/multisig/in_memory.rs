//! In-memory coordinator transport.

use super::types::{
    MultisigCoordinationMessage, MultisigCoordinator, MultisigMessageStream, MultisigTopic,
};
use async_trait::async_trait;
use futures_util::stream;
use krusty_kms_common::{KmsError, Result};
use std::collections::HashMap;
use tokio::sync::{broadcast, RwLock};

/// In-memory coordinator useful for tests and examples.
#[derive(Default)]
pub struct InMemoryMultisigCoordinator {
    messages: RwLock<HashMap<String, Vec<MultisigCoordinationMessage>>>,
    subscriptions: RwLock<HashMap<String, broadcast::Sender<MultisigCoordinationMessage>>>,
}

impl InMemoryMultisigCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl MultisigCoordinator for InMemoryMultisigCoordinator {
    async fn publish(&self, message: MultisigCoordinationMessage) -> Result<()> {
        if let MultisigCoordinationMessage::Proposal(proposal) = &message {
            proposal.validate_transaction_id()?;
        }

        let key = message.topic().key();
        let mut messages = self.messages.write().await;
        messages
            .entry(key.clone())
            .or_default()
            .push(message.clone());
        drop(messages);

        let sender = self.topic_sender(&key).await;
        let _ = sender.send(message);
        Ok(())
    }

    async fn messages(&self, topic: &MultisigTopic) -> Result<Vec<MultisigCoordinationMessage>> {
        let messages = self.messages.read().await;
        Ok(messages.get(&topic.key()).cloned().unwrap_or_default())
    }

    async fn subscribe(&self, topic: &MultisigTopic) -> Result<MultisigMessageStream> {
        let sender = self.topic_sender(&topic.key()).await;
        let receiver = sender.subscribe();
        Ok(Box::pin(stream::unfold(
            receiver,
            |mut receiver| async move {
                match receiver.recv().await {
                    Ok(message) => Some((Ok(message), receiver)),
                    Err(broadcast::error::RecvError::Lagged(count)) => Some((
                        Err(KmsError::MultisigError(format!(
                            "in-memory multisig subscription lagged by {count} messages"
                        ))),
                        receiver,
                    )),
                    Err(broadcast::error::RecvError::Closed) => None,
                }
            },
        )))
    }
}

impl InMemoryMultisigCoordinator {
    async fn topic_sender(&self, key: &str) -> broadcast::Sender<MultisigCoordinationMessage> {
        {
            let subscriptions = self.subscriptions.read().await;
            if let Some(sender) = subscriptions.get(key) {
                return sender.clone();
            }
        }

        let mut subscriptions = self.subscriptions.write().await;
        subscriptions
            .entry(key.to_string())
            .or_insert_with(|| {
                let (sender, _) = broadcast::channel(128);
                sender
            })
            .clone()
    }
}
