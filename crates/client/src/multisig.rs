//! OpenZeppelin Cairo multisig client and trusted coordination primitives.
//!
//! The OpenZeppelin multisig is an on-chain governance contract, not an
//! off-chain signature aggregator. A coordination server is useful for
//! distributing proposals and signer status, but Starknet remains the source of
//! truth: every submit, confirm, revoke, and execute action is still sent
//! through a registered signer account.

use crate::abi;
use crate::tx::Tx;
use crate::wallet::utils::{core_felt_to_rs, rs_felt_to_core};
use crate::wallet::WalletExecutor;
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{stream, Stream, StreamExt};
use krusty_kms_common::{Address, KmsError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use starknet_rust::core::types::{BlockId, BlockTag, Call, FunctionCall};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Provider;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, StarkHash};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use url::Url;

type StarknetRsFelt = starknet_rust::core::types::Felt;

/// Stream of coordination messages from a pub/sub backend.
pub type MultisigMessageStream =
    Pin<Box<dyn Stream<Item = Result<MultisigCoordinationMessage>> + Send>>;

/// Local representation of `starknet::account::Call` with stable JSON encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigCall {
    /// Target contract address.
    #[serde(with = "serde_address_hex")]
    pub to: Address,
    /// Entry point selector.
    #[serde(with = "serde_felt_hex")]
    pub selector: Felt,
    /// Raw Cairo calldata for the target call.
    #[serde(default, with = "serde_felt_hex_vec")]
    pub calldata: Vec<Felt>,
}

impl MultisigCall {
    /// Create a call from core Starknet types.
    #[must_use]
    pub fn new(to: Address, selector: Felt, calldata: Vec<Felt>) -> Self {
        Self {
            to,
            selector,
            calldata,
        }
    }

    /// Convert a `starknet-rs` call into the stable multisig call shape.
    #[must_use]
    pub fn from_starknet_call(call: &Call) -> Self {
        Self {
            to: Address::from(rs_felt_to_core(call.to)),
            selector: rs_felt_to_core(call.selector),
            calldata: call.calldata.iter().copied().map(rs_felt_to_core).collect(),
        }
    }

    /// Convert into the `starknet-rs` call shape used by wallet execution.
    #[must_use]
    pub fn to_starknet_call(&self) -> Call {
        Call {
            to: core_felt_to_rs(self.to.as_felt()),
            selector: core_felt_to_rs(self.selector),
            calldata: self.calldata.iter().copied().map(core_felt_to_rs).collect(),
        }
    }
}

/// State returned by `IMultisig::get_transaction_state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MultisigTransactionState {
    NotFound,
    Pending,
    Confirmed,
    Executed,
}

/// Pub/sub topic for one multisig transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigTopic {
    #[serde(with = "serde_address_hex")]
    pub multisig: Address,
    #[serde(with = "serde_felt_hex")]
    pub transaction_id: Felt,
}

impl MultisigTopic {
    #[must_use]
    fn key(&self) -> String {
        format!(
            "{}:{}",
            self.multisig.to_hex(),
            felt_to_hex(self.transaction_id)
        )
    }
}

/// Proposal payload distributed through a trusted coordination server.
///
/// `transaction_id` must equal [`hash_transaction_batch`] for `calls` and
/// `salt`. Receivers should call [`MultisigProposal::validate_transaction_id`]
/// before submitting confirmations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigProposal {
    #[serde(with = "serde_address_hex")]
    pub multisig: Address,
    #[serde(with = "serde_felt_hex")]
    pub transaction_id: Felt,
    pub calls: Vec<MultisigCall>,
    #[serde(with = "serde_felt_hex")]
    pub salt: Felt,
    #[serde(with = "serde_address_hex")]
    pub proposer: Address,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

impl MultisigProposal {
    /// Build a proposal and compute the canonical OpenZeppelin transaction ID.
    #[must_use]
    pub fn new(
        multisig: Address,
        calls: Vec<MultisigCall>,
        salt: Felt,
        proposer: Address,
        memo: Option<String>,
    ) -> Self {
        let transaction_id = hash_transaction_batch(&calls, salt);
        Self {
            multisig,
            transaction_id,
            calls,
            salt,
            proposer,
            memo,
        }
    }

    /// Return the coordination topic for this proposal.
    #[must_use]
    pub fn topic(&self) -> MultisigTopic {
        MultisigTopic {
            multisig: self.multisig,
            transaction_id: self.transaction_id,
        }
    }

    /// Recompute and validate the transaction ID.
    pub fn validate_transaction_id(&self) -> Result<()> {
        let expected = hash_transaction_batch(&self.calls, self.salt);
        if expected != self.transaction_id {
            return Err(KmsError::MultisigError(format!(
                "proposal transaction id {} does not match computed id {}",
                felt_to_hex(self.transaction_id),
                felt_to_hex(expected)
            )));
        }
        Ok(())
    }
}

/// Signer-scoped coordination notice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigSignerNotice {
    #[serde(with = "serde_address_hex")]
    pub multisig: Address,
    #[serde(with = "serde_felt_hex")]
    pub transaction_id: Felt,
    #[serde(with = "serde_address_hex")]
    pub signer: Address,
}

impl MultisigSignerNotice {
    #[must_use]
    pub fn new(multisig: Address, transaction_id: Felt, signer: Address) -> Self {
        Self {
            multisig,
            transaction_id,
            signer,
        }
    }

    #[must_use]
    pub fn topic(&self) -> MultisigTopic {
        MultisigTopic {
            multisig: self.multisig,
            transaction_id: self.transaction_id,
        }
    }
}

/// Execution notice distributed after a signer submits execution on-chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigExecutionNotice {
    #[serde(with = "serde_address_hex")]
    pub multisig: Address,
    #[serde(with = "serde_felt_hex")]
    pub transaction_id: Felt,
    #[serde(with = "serde_address_hex")]
    pub executor: Address,
}

impl MultisigExecutionNotice {
    #[must_use]
    pub fn new(multisig: Address, transaction_id: Felt, executor: Address) -> Self {
        Self {
            multisig,
            transaction_id,
            executor,
        }
    }

    #[must_use]
    pub fn topic(&self) -> MultisigTopic {
        MultisigTopic {
            multisig: self.multisig,
            transaction_id: self.transaction_id,
        }
    }
}

/// Message envelope exchanged through the trusted coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MultisigCoordinationMessage {
    Proposal(MultisigProposal),
    Confirmation(MultisigSignerNotice),
    Revocation(MultisigSignerNotice),
    Execution(MultisigExecutionNotice),
}

impl MultisigCoordinationMessage {
    /// Topic used for pub/sub routing.
    #[must_use]
    pub fn topic(&self) -> MultisigTopic {
        match self {
            Self::Proposal(proposal) => proposal.topic(),
            Self::Confirmation(notice) | Self::Revocation(notice) => notice.topic(),
            Self::Execution(notice) => notice.topic(),
        }
    }
}

/// Trusted coordination server boundary.
///
/// Implementations may use WebSockets, HTTP long polling, a durable message
/// bus, or any other trusted pub/sub system. The server distributes messages;
/// on-chain multisig checks still authorize every action.
#[async_trait]
pub trait MultisigCoordinator: Send + Sync {
    /// Publish one coordination message.
    async fn publish(&self, message: MultisigCoordinationMessage) -> Result<()>;

    /// Return known messages for a transaction topic.
    async fn messages(&self, _topic: &MultisigTopic) -> Result<Vec<MultisigCoordinationMessage>> {
        Err(KmsError::MultisigError(
            "coordinator does not expose retained message history".to_string(),
        ))
    }

    /// Subscribe to live pub/sub messages for a transaction topic.
    async fn subscribe(&self, _topic: &MultisigTopic) -> Result<MultisigMessageStream> {
        Err(KmsError::MultisigError(
            "coordinator does not expose live subscriptions".to_string(),
        ))
    }
}

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
    #[must_use]
    pub fn subject_for(subject_prefix: &str, topic: &MultisigTopic) -> String {
        format!(
            "{}.{}.{}",
            subject_prefix.trim_end_matches('.'),
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

        Ok(Box::pin(subscriber.map(|message| {
            serde_json::from_slice::<MultisigCoordinationMessage>(&message.payload)
                .map_err(|error| KmsError::MultisigError(error.to_string()))
        })))
    }
}

/// HTTP implementation of the trusted coordinator protocol.
///
/// Expected server API:
///
/// - `POST /v1/multisig/messages` with a [`MultisigCoordinationMessage`] JSON body.
/// - `GET /v1/multisig/messages?multisig=<addr>&transaction_id=<id>` returning
///   `Vec<MultisigCoordinationMessage>`.
#[derive(Clone)]
pub struct HttpMultisigCoordinator {
    base_url: Url,
    client: reqwest::Client,
}

impl HttpMultisigCoordinator {
    /// Create a coordinator from a parsed base URL.
    #[must_use]
    pub fn new(mut base_url: Url) -> Self {
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }

        Self {
            base_url,
            client: reqwest::Client::new(),
        }
    }

    /// Parse a coordinator base URL.
    ///
    /// Only `http`/`https` schemes are accepted. Loopback, link-local, and
    /// common cloud-metadata addresses are rejected to reduce SSRF risk.
    /// Use [`Self::from_url_unchecked`] in tests or when the caller has already
    /// validated the URL against a local allowlist.
    pub fn from_url(base_url: &str) -> Result<Self> {
        let url =
            Url::parse(base_url).map_err(|error| KmsError::MultisigError(error.to_string()))?;
        validate_coordinator_url(&url)?;
        Ok(Self::new(url))
    }

    /// Parse a coordinator URL without SSRF host/scheme checks.
    ///
    /// Intended for tests and explicitly trusted local tooling.
    pub fn from_url_unchecked(base_url: &str) -> Result<Self> {
        let url =
            Url::parse(base_url).map_err(|error| KmsError::MultisigError(error.to_string()))?;
        match url.scheme() {
            "http" | "https" => Ok(Self::new(url)),
            other => Err(KmsError::MultisigError(format!(
                "unsupported coordinator URL scheme '{other}' (only http/https)"
            ))),
        }
    }

    fn messages_url(&self) -> Result<Url> {
        self.base_url
            .join("v1/multisig/messages")
            .map_err(|error| KmsError::MultisigError(error.to_string()))
    }
}

fn validate_coordinator_url(url: &Url) -> Result<()> {
    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(KmsError::MultisigError(format!(
                "unsupported coordinator URL scheme '{other}' (only http/https)"
            )));
        }
    }

    let host = url
        .host_str()
        .ok_or_else(|| KmsError::MultisigError("coordinator URL missing host".to_string()))?;
    let host_lower = host.to_ascii_lowercase();

    if host_lower == "localhost"
        || host_lower.ends_with(".localhost")
        || host_lower == "metadata.google.internal"
    {
        return Err(KmsError::MultisigError(format!(
            "coordinator host '{host}' is blocked (loopback/metadata)"
        )));
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_blocked_ip(ip) {
            return Err(KmsError::MultisigError(format!(
                "coordinator host '{host}' is a blocked IP address"
            )));
        }
    }

    Ok(())
}

fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_link_local()
                || v4.octets() == [169, 254, 169, 254] // AWS/GCP metadata
                || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

#[async_trait]
impl MultisigCoordinator for HttpMultisigCoordinator {
    async fn publish(&self, message: MultisigCoordinationMessage) -> Result<()> {
        if let MultisigCoordinationMessage::Proposal(proposal) = &message {
            proposal.validate_transaction_id()?;
        }

        self.client
            .post(self.messages_url()?)
            .json(&message)
            .send()
            .await
            .map_err(|error| KmsError::MultisigError(error.to_string()))?
            .error_for_status()
            .map_err(|error| KmsError::MultisigError(error.to_string()))?;
        Ok(())
    }

    async fn messages(&self, topic: &MultisigTopic) -> Result<Vec<MultisigCoordinationMessage>> {
        let mut url = self.messages_url()?;
        url.query_pairs_mut()
            .append_pair("multisig", &topic.multisig.to_hex())
            .append_pair("transaction_id", &felt_to_hex(topic.transaction_id));

        self.client
            .get(url)
            .send()
            .await
            .map_err(|error| KmsError::MultisigError(error.to_string()))?
            .error_for_status()
            .map_err(|error| KmsError::MultisigError(error.to_string()))?
            .json::<Vec<MultisigCoordinationMessage>>()
            .await
            .map_err(|error| KmsError::MultisigError(error.to_string()))
    }
}

/// Client handle for an OpenZeppelin Cairo multisig contract.
pub struct Multisig {
    provider: Arc<JsonRpcClient<HttpTransport>>,
    address: Address,
}

impl Multisig {
    /// Create a multisig contract handle.
    #[must_use]
    pub fn new(provider: Arc<JsonRpcClient<HttpTransport>>, address: Address) -> Self {
        Self { provider, address }
    }

    /// The multisig contract address.
    #[must_use]
    pub fn address(&self) -> Address {
        self.address
    }

    /// Build a coordination proposal for a batch of calls.
    #[must_use]
    pub fn proposal(
        &self,
        calls: Vec<MultisigCall>,
        salt: Felt,
        proposer: Address,
        memo: Option<String>,
    ) -> MultisigProposal {
        MultisigProposal::new(self.address, calls, salt, proposer, memo)
    }

    /// Query the current quorum.
    pub async fn get_quorum(&self) -> Result<u32> {
        let result = self.call(*abi::multisig::GET_QUORUM, vec![]).await?;
        read_u32(&result, "get_quorum")
    }

    /// Query whether an address is a signer.
    pub async fn is_signer(&self, signer: &Address) -> Result<bool> {
        let result = self
            .call(
                *abi::multisig::IS_SIGNER,
                vec![core_felt_to_rs(signer.as_felt())],
            )
            .await?;
        read_bool(&result, "is_signer")
    }

    /// Query the current signer list.
    pub async fn get_signers(&self) -> Result<Vec<Address>> {
        let result = self.call(*abi::multisig::GET_SIGNERS, vec![]).await?;
        read_address_span(&result, "get_signers")
    }

    /// Query whether a transaction reached quorum.
    pub async fn is_confirmed(&self, id: Felt) -> Result<bool> {
        let result = self
            .call(*abi::multisig::IS_CONFIRMED, vec![core_felt_to_rs(id)])
            .await?;
        read_bool(&result, "is_confirmed")
    }

    /// Query whether `signer` confirmed a transaction.
    pub async fn is_confirmed_by(&self, id: Felt, signer: &Address) -> Result<bool> {
        let result = self
            .call(
                *abi::multisig::IS_CONFIRMED_BY,
                vec![core_felt_to_rs(id), core_felt_to_rs(signer.as_felt())],
            )
            .await?;
        read_bool(&result, "is_confirmed_by")
    }

    /// Query whether a transaction has executed.
    pub async fn is_executed(&self, id: Felt) -> Result<bool> {
        let result = self
            .call(*abi::multisig::IS_EXECUTED, vec![core_felt_to_rs(id)])
            .await?;
        read_bool(&result, "is_executed")
    }

    /// Query the block number where a transaction was submitted.
    pub async fn get_submitted_block(&self, id: Felt) -> Result<u64> {
        let result = self
            .call(
                *abi::multisig::GET_SUBMITTED_BLOCK,
                vec![core_felt_to_rs(id)],
            )
            .await?;
        read_u64(&result, "get_submitted_block")
    }

    /// Query the current transaction state.
    pub async fn get_transaction_state(&self, id: Felt) -> Result<MultisigTransactionState> {
        let result = self
            .call(
                *abi::multisig::GET_TRANSACTION_STATE,
                vec![core_felt_to_rs(id)],
            )
            .await?;
        read_transaction_state(&result)
    }

    /// Query the count of confirmations from current registered signers.
    pub async fn get_transaction_confirmations(&self, id: Felt) -> Result<u32> {
        let result = self
            .call(
                *abi::multisig::GET_TRANSACTION_CONFIRMATIONS,
                vec![core_felt_to_rs(id)],
            )
            .await?;
        read_u32(&result, "get_transaction_confirmations")
    }

    /// Ask the contract to hash a single-call transaction.
    pub async fn hash_transaction_onchain(&self, call: &MultisigCall, salt: Felt) -> Result<Felt> {
        let result = self
            .call(
                *abi::multisig::HASH_TRANSACTION,
                serialize_single_call_args(call, salt),
            )
            .await?;
        read_felt(&result, "hash_transaction")
    }

    /// Ask the contract to hash a batch transaction.
    pub async fn hash_transaction_batch_onchain(
        &self,
        calls: &[MultisigCall],
        salt: Felt,
    ) -> Result<Felt> {
        let result = self
            .call(
                *abi::multisig::HASH_TRANSACTION_BATCH,
                serialize_batch_call_args(calls, salt),
            )
            .await?;
        read_felt(&result, "hash_transaction_batch")
    }

    /// Build an `add_signers` self-admin call.
    #[must_use]
    pub fn populate_add_signers(&self, new_quorum: u32, signers_to_add: &[Address]) -> Call {
        self.call_to_multisig(
            *abi::multisig::ADD_SIGNERS,
            serialize_quorum_and_signers(new_quorum, signers_to_add),
        )
    }

    /// Build a `remove_signers` self-admin call.
    #[must_use]
    pub fn populate_remove_signers(&self, new_quorum: u32, signers_to_remove: &[Address]) -> Call {
        self.call_to_multisig(
            *abi::multisig::REMOVE_SIGNERS,
            serialize_quorum_and_signers(new_quorum, signers_to_remove),
        )
    }

    /// Build a `replace_signer` self-admin call.
    #[must_use]
    pub fn populate_replace_signer(
        &self,
        signer_to_remove: &Address,
        signer_to_add: &Address,
    ) -> Call {
        self.call_to_multisig(
            *abi::multisig::REPLACE_SIGNER,
            vec![
                core_felt_to_rs(signer_to_remove.as_felt()),
                core_felt_to_rs(signer_to_add.as_felt()),
            ],
        )
    }

    /// Build a `change_quorum` self-admin call.
    #[must_use]
    pub fn populate_change_quorum(&self, new_quorum: u32) -> Call {
        self.call_to_multisig(
            *abi::multisig::CHANGE_QUORUM,
            vec![core_felt_to_rs(Felt::from(new_quorum))],
        )
    }

    /// Build a `submit_transaction` call.
    #[must_use]
    pub fn populate_submit(&self, call: &MultisigCall, salt: Felt) -> Call {
        self.call_to_multisig(
            *abi::multisig::SUBMIT_TRANSACTION,
            serialize_single_call_args(call, salt),
        )
    }

    /// Build a `submit_transaction_batch` call.
    #[must_use]
    pub fn populate_submit_batch(&self, calls: &[MultisigCall], salt: Felt) -> Call {
        self.call_to_multisig(
            *abi::multisig::SUBMIT_TRANSACTION_BATCH,
            serialize_batch_call_args(calls, salt),
        )
    }

    /// Build a `confirm_transaction` call.
    #[must_use]
    pub fn populate_confirm(&self, id: Felt) -> Call {
        self.call_to_multisig(
            *abi::multisig::CONFIRM_TRANSACTION,
            vec![core_felt_to_rs(id)],
        )
    }

    /// Build a `revoke_confirmation` call.
    #[must_use]
    pub fn populate_revoke(&self, id: Felt) -> Call {
        self.call_to_multisig(
            *abi::multisig::REVOKE_CONFIRMATION,
            vec![core_felt_to_rs(id)],
        )
    }

    /// Build an `execute_transaction` call.
    #[must_use]
    pub fn populate_execute(&self, call: &MultisigCall, salt: Felt) -> Call {
        self.call_to_multisig(
            *abi::multisig::EXECUTE_TRANSACTION,
            serialize_single_call_args(call, salt),
        )
    }

    /// Build an `execute_transaction_batch` call.
    #[must_use]
    pub fn populate_execute_batch(&self, calls: &[MultisigCall], salt: Felt) -> Call {
        self.call_to_multisig(
            *abi::multisig::EXECUTE_TRANSACTION_BATCH,
            serialize_batch_call_args(calls, salt),
        )
    }

    /// Submit a batch proposal on-chain through a registered signer wallet.
    pub async fn submit_batch(
        &self,
        wallet: &dyn WalletExecutor,
        calls: &[MultisigCall],
        salt: Felt,
    ) -> Result<Tx> {
        wallet
            .execute(vec![self.populate_submit_batch(calls, salt)])
            .await
    }

    /// Confirm a submitted transaction on-chain through a registered signer wallet.
    pub async fn confirm(&self, wallet: &dyn WalletExecutor, id: Felt) -> Result<Tx> {
        wallet.execute(vec![self.populate_confirm(id)]).await
    }

    /// Revoke a previous confirmation on-chain.
    pub async fn revoke(&self, wallet: &dyn WalletExecutor, id: Felt) -> Result<Tx> {
        wallet.execute(vec![self.populate_revoke(id)]).await
    }

    /// Execute a confirmed batch transaction on-chain.
    pub async fn execute_batch(
        &self,
        wallet: &dyn WalletExecutor,
        calls: &[MultisigCall],
        salt: Felt,
    ) -> Result<Tx> {
        wallet
            .execute(vec![self.populate_execute_batch(calls, salt)])
            .await
    }

    async fn call(
        &self,
        selector: StarknetRsFelt,
        calldata: Vec<StarknetRsFelt>,
    ) -> Result<Vec<StarknetRsFelt>> {
        self.provider
            .call(
                FunctionCall {
                    contract_address: core_felt_to_rs(self.address.as_felt()),
                    entry_point_selector: selector,
                    calldata,
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
            .map_err(|error| KmsError::RpcError(error.to_string()))
    }

    fn call_to_multisig(&self, selector: StarknetRsFelt, calldata: Vec<StarknetRsFelt>) -> Call {
        Call {
            to: core_felt_to_rs(self.address.as_felt()),
            selector,
            calldata,
        }
    }
}

/// Compute the OpenZeppelin multisig transaction ID for one call.
#[must_use]
pub fn hash_transaction(call: &MultisigCall, salt: Felt) -> Felt {
    hash_transaction_batch(std::slice::from_ref(call), salt)
}

/// Compute the OpenZeppelin multisig transaction ID for a batch of calls.
///
/// This mirrors `PedersenTrait::new(0).update_with(calls).update_with(salt)`
/// and the `Hash<Call>` implementation in OpenZeppelin Cairo contracts:
/// `[calls_len, to, selector, calldata_len, calldata..., salt]`.
#[must_use]
pub fn hash_transaction_batch(calls: &[MultisigCall], salt: Felt) -> Felt {
    let mut state = Felt::ZERO;
    state = pedersen_update(state, Felt::from(calls.len() as u64));
    for call in calls {
        state = pedersen_update(state, call.to.as_felt());
        state = pedersen_update(state, call.selector);
        state = pedersen_update(state, Felt::from(call.calldata.len() as u64));
        for value in &call.calldata {
            state = pedersen_update(state, *value);
        }
    }
    pedersen_update(state, salt)
}

fn pedersen_update(state: Felt, value: Felt) -> Felt {
    Pedersen::hash(&state, &value)
}

fn serialize_single_call_args(call: &MultisigCall, salt: Felt) -> Vec<StarknetRsFelt> {
    let mut calldata = Vec::with_capacity(call.calldata.len() + 4);
    calldata.push(core_felt_to_rs(call.to.as_felt()));
    calldata.push(core_felt_to_rs(call.selector));
    calldata.push(core_felt_to_rs(Felt::from(call.calldata.len() as u64)));
    calldata.extend(call.calldata.iter().copied().map(core_felt_to_rs));
    calldata.push(core_felt_to_rs(salt));
    calldata
}

fn serialize_batch_call_args(calls: &[MultisigCall], salt: Felt) -> Vec<StarknetRsFelt> {
    let mut calldata = serialize_call_span(calls);
    calldata.push(core_felt_to_rs(salt));
    calldata
}

fn serialize_call_span(calls: &[MultisigCall]) -> Vec<StarknetRsFelt> {
    let calldata_len = calls.iter().map(|call| call.calldata.len()).sum::<usize>();
    let mut calldata = Vec::with_capacity(1 + calls.len() * 3 + calldata_len);
    calldata.push(core_felt_to_rs(Felt::from(calls.len() as u64)));
    for call in calls {
        calldata.push(core_felt_to_rs(call.to.as_felt()));
        calldata.push(core_felt_to_rs(call.selector));
        calldata.push(core_felt_to_rs(Felt::from(call.calldata.len() as u64)));
        calldata.extend(call.calldata.iter().copied().map(core_felt_to_rs));
    }
    calldata
}

fn serialize_quorum_and_signers(new_quorum: u32, signers: &[Address]) -> Vec<StarknetRsFelt> {
    let mut calldata = Vec::with_capacity(signers.len() + 2);
    calldata.push(core_felt_to_rs(Felt::from(new_quorum)));
    calldata.push(core_felt_to_rs(Felt::from(signers.len() as u64)));
    calldata.extend(
        signers
            .iter()
            .map(|signer| core_felt_to_rs(signer.as_felt())),
    );
    calldata
}

fn read_felt(result: &[StarknetRsFelt], name: &str) -> Result<Felt> {
    result
        .first()
        .copied()
        .map(rs_felt_to_core)
        .ok_or_else(|| KmsError::DeserializationError(format!("empty response from {name}")))
}

fn read_bool(result: &[StarknetRsFelt], name: &str) -> Result<bool> {
    Ok(read_felt(result, name)? != Felt::ZERO)
}

fn read_u32(result: &[StarknetRsFelt], name: &str) -> Result<u32> {
    let bytes = read_felt(result, name)?.to_bytes_be();
    let mut value = [0u8; 4];
    value.copy_from_slice(&bytes[28..32]);
    Ok(u32::from_be_bytes(value))
}

fn read_u64(result: &[StarknetRsFelt], name: &str) -> Result<u64> {
    let bytes = read_felt(result, name)?.to_bytes_be();
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[24..32]);
    Ok(u64::from_be_bytes(value))
}

fn read_usize(result: &StarknetRsFelt, name: &str) -> Result<usize> {
    let bytes = rs_felt_to_core(*result).to_bytes_be();
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[24..32]);
    usize::try_from(u64::from_be_bytes(value)).map_err(|error| {
        KmsError::DeserializationError(format!("invalid usize response from {name}: {error}"))
    })
}

fn read_address_span(result: &[StarknetRsFelt], name: &str) -> Result<Vec<Address>> {
    let Some(first) = result.first() else {
        return Err(KmsError::DeserializationError(format!(
            "empty response from {name}"
        )));
    };

    let count = read_usize(first, name)?;
    if result.len() != count + 1 {
        return Err(KmsError::DeserializationError(format!(
            "unexpected {name} response length: expected {}, got {}",
            count + 1,
            result.len()
        )));
    }

    Ok(result[1..]
        .iter()
        .copied()
        .map(rs_felt_to_core)
        .map(Address::from)
        .collect())
}

fn read_transaction_state(result: &[StarknetRsFelt]) -> Result<MultisigTransactionState> {
    match read_u32(result, "get_transaction_state")? {
        0 => Ok(MultisigTransactionState::NotFound),
        1 => Ok(MultisigTransactionState::Pending),
        2 => Ok(MultisigTransactionState::Confirmed),
        3 => Ok(MultisigTransactionState::Executed),
        value => Err(KmsError::DeserializationError(format!(
            "unknown multisig transaction state {value}"
        ))),
    }
}

fn felt_to_hex(felt: Felt) -> String {
    format!("0x{:064x}", felt)
}

fn felt_subject_token(felt: Felt) -> String {
    felt_to_hex(felt).trim_start_matches("0x").to_string()
}

fn address_subject_token(address: Address) -> String {
    felt_subject_token(address.as_felt())
}

fn parse_felt_hex(value: &str) -> std::result::Result<Felt, String> {
    Felt::from_hex(value).map_err(|error| error.to_string())
}

mod serde_felt_hex {
    use super::*;

    pub fn serialize<S>(felt: &Felt, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&felt_to_hex(*felt))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Felt, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        parse_felt_hex(&value).map_err(serde::de::Error::custom)
    }
}

mod serde_felt_hex_vec {
    use super::*;

    pub fn serialize<S>(felts: &[Felt], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = felts.iter().copied().map(felt_to_hex).collect::<Vec<_>>();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Vec<Felt>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<String>::deserialize(deserializer)?;
        values
            .iter()
            .map(|value| parse_felt_hex(value).map_err(serde::de::Error::custom))
            .collect()
    }
}

mod serde_address_hex {
    use super::*;

    pub fn serialize<S>(address: &Address, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&address.to_hex())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Address, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Address::from_hex(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(value: u64) -> Address {
        Address::from(Felt::from(value))
    }

    fn call() -> MultisigCall {
        MultisigCall::new(
            address(0xabc),
            Felt::from(0x123u64),
            vec![Felt::from(7u64), Felt::from(8u64)],
        )
    }

    #[test]
    fn test_single_call_calldata_serialization() {
        let encoded = serialize_single_call_args(&call(), Felt::from(99u64));
        let decoded = encoded.into_iter().map(rs_felt_to_core).collect::<Vec<_>>();
        assert_eq!(
            decoded,
            vec![
                Felt::from(0xabcu64),
                Felt::from(0x123u64),
                Felt::from(2u64),
                Felt::from(7u64),
                Felt::from(8u64),
                Felt::from(99u64),
            ]
        );
    }

    #[test]
    fn test_batch_call_calldata_serialization() {
        let calls = vec![
            call(),
            MultisigCall::new(address(0xdef), Felt::from(0x456u64), vec![]),
        ];
        let encoded = serialize_batch_call_args(&calls, Felt::from(99u64));
        let decoded = encoded.into_iter().map(rs_felt_to_core).collect::<Vec<_>>();
        assert_eq!(
            decoded,
            vec![
                Felt::from(2u64),
                Felt::from(0xabcu64),
                Felt::from(0x123u64),
                Felt::from(2u64),
                Felt::from(7u64),
                Felt::from(8u64),
                Felt::from(0xdefu64),
                Felt::from(0x456u64),
                Felt::from(0u64),
                Felt::from(99u64),
            ]
        );
    }

    #[test]
    fn test_transaction_hash_changes_with_salt() {
        let call = call();
        let first = hash_transaction(&call, Felt::from(1u64));
        let second = hash_transaction(&call, Felt::from(2u64));
        assert_ne!(first, second);
    }

    #[test]
    fn test_proposal_json_uses_hex_felts() {
        let proposal = MultisigProposal::new(
            address(1),
            vec![call()],
            Felt::from(99u64),
            address(2),
            Some("rotate signer".to_string()),
        );
        let json = serde_json::to_string(&proposal).unwrap();
        assert!(json.contains("0x0000000000000000000000000000000000000000000000000000000000000063"));
        let roundtrip: MultisigProposal = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip, proposal);
        roundtrip.validate_transaction_id().unwrap();
    }

    #[tokio::test]
    async fn test_in_memory_coordinator_routes_by_topic() {
        let coordinator = InMemoryMultisigCoordinator::new();
        let proposal = MultisigProposal::new(
            address(1),
            vec![call()],
            Felt::from(99u64),
            address(2),
            None,
        );
        let topic = proposal.topic();

        coordinator
            .publish(MultisigCoordinationMessage::Proposal(proposal.clone()))
            .await
            .unwrap();
        coordinator
            .publish(MultisigCoordinationMessage::Confirmation(
                MultisigSignerNotice::new(address(1), proposal.transaction_id, address(3)),
            ))
            .await
            .unwrap();

        let messages = coordinator.messages(&topic).await.unwrap();
        assert_eq!(messages.len(), 2);
    }

    #[tokio::test]
    async fn test_in_memory_coordinator_live_subscription() {
        let coordinator = InMemoryMultisigCoordinator::new();
        let proposal = MultisigProposal::new(
            address(1),
            vec![call()],
            Felt::from(99u64),
            address(2),
            None,
        );
        let mut subscription = coordinator.subscribe(&proposal.topic()).await.unwrap();

        coordinator
            .publish(MultisigCoordinationMessage::Proposal(proposal.clone()))
            .await
            .unwrap();

        let received = subscription.next().await.unwrap().unwrap();
        assert_eq!(received, MultisigCoordinationMessage::Proposal(proposal));
    }

    #[tokio::test]
    async fn test_in_memory_coordinator_rejects_tampered_proposal() {
        let coordinator = InMemoryMultisigCoordinator::new();
        let mut proposal = MultisigProposal::new(
            address(1),
            vec![call()],
            Felt::from(99u64),
            address(2),
            None,
        );
        proposal.transaction_id = Felt::from(1u64);

        assert!(matches!(
            coordinator
                .publish(MultisigCoordinationMessage::Proposal(proposal))
                .await,
            Err(KmsError::MultisigError(_))
        ));
    }

    #[test]
    fn test_http_coordinator_preserves_base_path() {
        let coordinator =
            HttpMultisigCoordinator::from_url("https://coordinator.example/api").unwrap();
        assert_eq!(
            coordinator.messages_url().unwrap().as_str(),
            "https://coordinator.example/api/v1/multisig/messages"
        );
    }

    #[test]
    fn test_http_coordinator_rejects_dangerous_urls() {
        assert!(HttpMultisigCoordinator::from_url("file:///etc/passwd").is_err());
        assert!(HttpMultisigCoordinator::from_url("http://localhost:8080").is_err());
        assert!(HttpMultisigCoordinator::from_url("http://127.0.0.1/").is_err());
        assert!(HttpMultisigCoordinator::from_url("http://169.254.169.254/").is_err());
        assert!(HttpMultisigCoordinator::from_url_unchecked("http://127.0.0.1/").is_ok());
    }

    #[test]
    fn test_nats_subject_is_deterministic() {
        let topic = MultisigTopic {
            multisig: address(1),
            transaction_id: Felt::from(2u64),
        };

        assert_eq!(
            NatsMultisigCoordinator::subject_for("krusty.multisig.", &topic),
            "krusty.multisig.0000000000000000000000000000000000000000000000000000000000000001.0000000000000000000000000000000000000000000000000000000000000002"
        );
    }
}
