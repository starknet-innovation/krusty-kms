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
use krusty_kms_common::{Address, ChainId, KmsError, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use starknet_rust::core::types::{BlockId, BlockTag, Call, FunctionCall};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Provider;
use starknet_types_core::felt::Felt;
use starknet_types_core::hash::{Pedersen, StarkHash};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
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
///
/// The chain is part of the routing key so a proposal replayed to a shared
/// coordinator cannot leak onto another network's topic, and a subscriber on
/// one chain never sees the other chain's messages for the same
/// multisig/transaction-id pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigTopic {
    #[serde(with = "serde_address_hex")]
    pub multisig: Address,
    pub chain_id: ChainId,
    #[serde(with = "serde_felt_hex")]
    pub transaction_id: Felt,
}

impl MultisigTopic {
    #[must_use]
    fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.chain_id,
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
    /// Chain the proposal was created for. The transaction id hash covers
    /// only `calls`/`salt`, so without this field a proposal replayed through
    /// a shared or compromised coordinator would also validate on another
    /// network where the same multisig address/id exists.
    pub chain_id: ChainId,
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
    ///
    /// The transaction id intentionally matches the on-chain hash (calls and
    /// salt only); the chain binding lives in the `chain_id` envelope field.
    #[must_use]
    pub fn new(
        multisig: Address,
        chain_id: ChainId,
        calls: Vec<MultisigCall>,
        salt: Felt,
        proposer: Address,
        memo: Option<String>,
    ) -> Self {
        let transaction_id = hash_transaction_batch(&calls, salt);
        Self {
            multisig,
            chain_id,
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
            chain_id: self.chain_id,
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
    /// Chain this notice belongs to; part of the routing topic.
    pub chain_id: ChainId,
    #[serde(with = "serde_felt_hex")]
    pub transaction_id: Felt,
    #[serde(with = "serde_address_hex")]
    pub signer: Address,
}

impl MultisigSignerNotice {
    #[must_use]
    pub fn new(
        multisig: Address,
        chain_id: ChainId,
        transaction_id: Felt,
        signer: Address,
    ) -> Self {
        Self {
            multisig,
            chain_id,
            transaction_id,
            signer,
        }
    }

    #[must_use]
    pub fn topic(&self) -> MultisigTopic {
        MultisigTopic {
            multisig: self.multisig,
            chain_id: self.chain_id,
            transaction_id: self.transaction_id,
        }
    }
}

/// Execution notice distributed after a signer submits execution on-chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigExecutionNotice {
    #[serde(with = "serde_address_hex")]
    pub multisig: Address,
    /// Chain this notice belongs to; part of the routing topic.
    pub chain_id: ChainId,
    #[serde(with = "serde_felt_hex")]
    pub transaction_id: Felt,
    #[serde(with = "serde_address_hex")]
    pub executor: Address,
}

impl MultisigExecutionNotice {
    #[must_use]
    pub fn new(
        multisig: Address,
        chain_id: ChainId,
        transaction_id: Felt,
        executor: Address,
    ) -> Self {
        Self {
            multisig,
            chain_id,
            transaction_id,
            executor,
        }
    }

    #[must_use]
    pub fn topic(&self) -> MultisigTopic {
        MultisigTopic {
            multisig: self.multisig,
            chain_id: self.chain_id,
            transaction_id: self.transaction_id,
        }
    }
}

/// Message envelope exchanged through the trusted coordinator.
///
/// All variants are advisory: the claimed `signer`/`executor`/`proposer` is
/// not authenticated by the coordinator, so a compromised coordinator can
/// forge notices. This is safe only because no on-chain action is authorized
/// by these messages — the multisig contract re-checks quorum and signer
/// authorization on-chain, and [`Multisig::confirm_proposal`] re-derives the
/// transaction id from the proposal payload before signing. Consumers must
/// treat notices as hints (e.g. "check chain state"), never as proof that an
/// action happened.
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

/// Receive-side validation for messages arriving from a coordinator.
///
/// The coordinator is a distribution boundary, not an authorization boundary:
/// nothing on the receive path is authenticated by the server. Every message
/// pulled from `subscribe`/`messages` must therefore be checked before it
/// drives an on-chain action:
///
/// - the message topic must match the subscribed topic (defends against
///   cross-topic replay/misrouting by a compromised coordinator), and
/// - a proposal's `transaction_id` must recompute from its `calls`/`salt`
///   (defends against confirmations bound to a forged id).
fn validate_incoming_message(
    topic: &MultisigTopic,
    message: &MultisigCoordinationMessage,
) -> Result<()> {
    if &message.topic() != topic {
        return Err(KmsError::MultisigError(
            "coordination message topic does not match the subscribed topic".to_string(),
        ));
    }
    if let MultisigCoordinationMessage::Proposal(proposal) = message {
        proposal.validate_transaction_id()?;
    }
    Ok(())
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

    fn messages_url(&self) -> Result<Url> {
        self.base_url
            .join("v1/multisig/messages")
            .map_err(|error| KmsError::MultisigError(error.to_string()))
    }
}

#[derive(Debug)]
struct SsrfBlockedRedirect(String);

impl std::fmt::Display for SsrfBlockedRedirect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SsrfBlockedRedirect {}

/// DNS resolver that rejects non-public addresses on every lookup.
///
/// Used by the SSRF-safe HTTP client so connection-time resolution cannot
/// rebind to an internal IP after a successful preflight check.
#[derive(Debug, Default)]
struct PublicOnlyResolver;

impl reqwest::dns::Resolve for PublicOnlyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let raw = name.as_str().trim_end_matches('.');
            // reqwest may pass IPv6 literals with brackets; strip them so we can
            // apply the same IP policy without a spurious DNS lookup.
            let host = raw
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(raw);

            if let Ok(ip) = host.parse::<IpAddr>() {
                if is_blocked_ip(ip) {
                    return Err(Box::new(std::io::Error::other(format!(
                        "coordinator host '{host}' is a blocked IP address"
                    )))
                        as Box<dyn std::error::Error + Send + Sync>);
                }
                let iter: reqwest::dns::Addrs = Box::new(std::iter::once(SocketAddr::new(ip, 0)));
                return Ok(iter);
            }

            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, 0))
                .await
                .map_err(|error| {
                    Box::new(std::io::Error::other(format!(
                        "DNS resolve failed for '{host}': {error}"
                    ))) as Box<dyn std::error::Error + Send + Sync>
                })?
                .collect();

            if addrs.is_empty() {
                return Err(Box::new(std::io::Error::other(format!(
                    "coordinator host '{host}' resolved to no addresses"
                )))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            // Fail closed if any address is non-public (rebinding / mixed RRset).
            if addrs.iter().any(|addr| is_blocked_ip(addr.ip())) {
                return Err(Box::new(std::io::Error::other(format!(
                    "coordinator host '{host}' resolved to a blocked address"
                )))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            let iter: reqwest::dns::Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

fn build_ssrf_safe_client(url: &Url) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        // Bypass env/system proxies so DNS pinning and PublicOnlyResolver
        // apply to the actual coordinator destination (not a proxy hop).
        .no_proxy()
        .dns_resolver(Arc::new(PublicOnlyResolver))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 10 {
                return attempt.error(SsrfBlockedRedirect(
                    "too many redirects while contacting coordinator".to_string(),
                ));
            }
            match validate_coordinator_url(attempt.url()) {
                Ok(()) => attempt.follow(),
                Err(error) => attempt.error(SsrfBlockedRedirect(error.to_string())),
            }
        }));

    // Pin the initially validated public addresses for the base host so the
    // first connection cannot race a different A/AAAA set. Redirects to other
    // hosts still go through PublicOnlyResolver.
    if let Some(url::Host::Domain(domain)) = url.host() {
        let port = url.port_or_known_default().unwrap_or(80);
        let addrs = resolve_public_socket_addrs(domain, port)?;
        builder = builder.resolve_to_addrs(domain, &addrs);
    }

    builder
        .build()
        .map_err(|error| KmsError::MultisigError(error.to_string()))
}

fn resolve_public_socket_addrs(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|error| {
            KmsError::MultisigError(format!(
                "failed to resolve coordinator host '{host}': {error}"
            ))
        })?
        .collect();

    if addrs.is_empty() {
        return Err(KmsError::MultisigError(format!(
            "coordinator host '{host}' resolved to no addresses"
        )));
    }

    for addr in &addrs {
        if is_blocked_ip(addr.ip()) {
            return Err(KmsError::MultisigError(format!(
                "coordinator host '{host}' resolves to blocked address {}",
                addr.ip()
            )));
        }
    }

    Ok(addrs)
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
        .host()
        .ok_or_else(|| KmsError::MultisigError("coordinator URL missing host".to_string()))?;

    match host {
        url::Host::Ipv4(v4) => {
            if is_blocked_ipv4(v4) {
                return Err(KmsError::MultisigError(format!(
                    "coordinator host '{v4}' is a blocked IP address"
                )));
            }
            Ok(())
        }
        url::Host::Ipv6(v6) => {
            // Prefer `url::Host::Ipv6` over `host_str()`: the latter includes
            // brackets, which break `IpAddr` parsing and skipped IPv6 SSRF checks.
            if is_blocked_ip(IpAddr::V6(v6)) {
                return Err(KmsError::MultisigError(format!(
                    "coordinator host '{v6}' is a blocked IP address"
                )));
            }
            Ok(())
        }
        url::Host::Domain(domain) => {
            let host_lower = domain.to_ascii_lowercase();
            if host_lower == "localhost"
                || host_lower.ends_with(".localhost")
                || host_lower == "metadata.google.internal"
            {
                return Err(KmsError::MultisigError(format!(
                    "coordinator host '{domain}' is blocked (loopback/metadata)"
                )));
            }

            let port = url.port_or_known_default().unwrap_or(80);
            // Hostname: resolve and require every address to be publicly routable.
            let _ = resolve_public_socket_addrs(domain, port)?;
            Ok(())
        }
    }
}

/// Returns true for non-public / special-use addresses (SSRF targets).
fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_ipv4(v4);
            }
            // NAT64 / IPv4-translation prefixes (RFC 6052 / RFC 8215): reject
            // when the embedded IPv4 destination is itself blocked.
            if let Some(v4) = ipv4_from_nat64_prefix(v6) {
                return is_blocked_ipv4(v4);
            }
            // Local-use NAT64 `64:ff9b:1::/48` with a non-/96 layout we cannot
            // decode — fail closed rather than allow a private embedding.
            if is_local_use_nat64_prefix(v6) {
                return true;
            }
            // Legacy transition formats (6to4, IPv4-compatible) embed an IPv4
            // destination the same way NAT64 does.
            if let Some(v4) = ipv4_from_transition_prefix(v6) {
                return is_blocked_ipv4(v4);
            }
            is_blocked_ipv6(v6)
        }
    }
}

fn is_blocked_ipv4(v4: Ipv4Addr) -> bool {
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_documentation()
        || v4.is_unspecified()
        || v4.is_multicast()
        || v4.octets()[0] == 0
        // CGNAT 100.64.0.0/10
        || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 0b0100_0000)
        // AWS/GCP metadata
        || v4.octets() == [169, 254, 169, 254]
        // IETF Protocol Assignments 192.0.0.0/24 (except .9/.10 sometimes)
        || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0)
        // Benchmarking 198.18.0.0/15
        || (v4.octets()[0] == 198 && (v4.octets()[1] == 18 || v4.octets()[1] == 19))
        // Reserved / future use 240.0.0.0/4
        || v4.octets()[0] >= 240
}

fn is_blocked_ipv6(v6: Ipv6Addr) -> bool {
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || v6.is_unicast_link_local()
        || v6.is_unique_local()
        // Deprecated site-local fec0::/10 (RFC 3879) — still routed internally
        // on some networks, so treat it like the other private ranges.
        || (v6.segments()[0] & 0xffc0) == 0xfec0
        // Documentation 2001:db8::/32
        || v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8
        // Discard prefix 100::/64
        || (v6.segments()[0] == 0x0100 && v6.segments()[1..4] == [0, 0, 0])
}

fn ipv4_from_u16_pair(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8)
}

/// Extract an IPv4 address embedded in a NAT64 translation prefix.
///
/// Handles:
/// - RFC 6052 well-known prefix `64:ff9b::/96` (IPv4 in the last 32 bits)
/// - RFC 8215 local-use prefix `64:ff9b:1::/48` with `/96`-style embedding
///   (e.g. `64:ff9b:1::a00:1` → `10.0.0.1`)
/// - RFC 6052 PLEN=48 embedding under the local-use prefix
fn ipv4_from_nat64_prefix(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();

    // Well-known NAT64 prefix 64:ff9b::/96
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return Some(ipv4_from_u16_pair(s[6], s[7]));
    }

    // Local-use NAT64 64:ff9b:1::/48 with /96-style suffix (Codex example).
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return Some(ipv4_from_u16_pair(s[6], s[7]));
    }

    // RFC 6052 PLEN=48 under local-use: IPv4 in bits 48-63 and 72-87
    // (bits 64-71 are the "u" octet and must be zero).
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001 && (s[4] >> 8) == 0 {
        return Some(Ipv4Addr::new(
            (s[3] >> 8) as u8,
            s[3] as u8,
            s[4] as u8,
            (s[5] >> 8) as u8,
        ));
    }

    None
}

fn is_local_use_nat64_prefix(v6: Ipv6Addr) -> bool {
    let s = v6.segments();
    s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001
}

/// Extract an IPv4 address embedded in a legacy IPv6 transition format.
///
/// Handles:
/// - 6to4 `2002::/16` (RFC 3056), IPv4 in bits 16-47
/// - deprecated IPv4-compatible `::a.b.c.d` (RFC 4291), IPv4 in the low 32 bits
fn ipv4_from_transition_prefix(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();

    // 6to4 2002::/16 — e.g. `2002:0a00:0001::` → 10.0.0.1
    if s[0] == 0x2002 {
        return Some(ipv4_from_u16_pair(s[1], s[2]));
    }

    // IPv4-compatible ::a.b.c.d — e.g. `::a00:1` → 10.0.0.1
    if s[..6] == [0, 0, 0, 0, 0, 0] && (s[6], s[7]) != (0, 0) {
        return Some(ipv4_from_u16_pair(s[6], s[7]));
    }

    None
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
            .append_pair("chain_id", topic.chain_id.name())
            .append_pair("transaction_id", &felt_to_hex(topic.transaction_id));

        let messages = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|error| KmsError::MultisigError(error.to_string()))?
            .error_for_status()
            .map_err(|error| KmsError::MultisigError(error.to_string()))?
            .json::<Vec<MultisigCoordinationMessage>>()
            .await
            .map_err(|error| KmsError::MultisigError(error.to_string()))?;

        // Receive-side validation: the coordinator response is untrusted.
        for message in &messages {
            validate_incoming_message(topic, message)?;
        }
        Ok(messages)
    }
}

/// Client handle for an OpenZeppelin Cairo multisig contract.
pub struct Multisig {
    provider: Arc<JsonRpcClient<HttpTransport>>,
    address: Address,
    chain_id: ChainId,
}

impl Multisig {
    /// Create a multisig contract handle.
    ///
    /// `chain_id` is the network the contract lives on; [`Self::confirm_proposal`]
    /// refuses to sign with a wallet bound to a different chain, so a proposal
    /// replayed across networks (the transaction id hash does not bind a chain)
    /// cannot collect confirmations there.
    #[must_use]
    pub fn new(
        provider: Arc<JsonRpcClient<HttpTransport>>,
        address: Address,
        chain_id: ChainId,
    ) -> Self {
        Self {
            provider,
            address,
            chain_id,
        }
    }

    /// The multisig contract address.
    #[must_use]
    pub fn address(&self) -> Address {
        self.address
    }

    /// The chain this handle expects the contract and signers to live on.
    #[must_use]
    pub fn chain_id(&self) -> ChainId {
        self.chain_id
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
        MultisigProposal::new(self.address, self.chain_id, calls, salt, proposer, memo)
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
    ///
    /// `id` is trusted as-is and signed without any validation. **Do not** pass
    /// an id taken from a coordinator message: those arrive unauthenticated and
    /// a compromised coordinator can forge them. Use [`Self::confirm_proposal`]
    /// for coordinator-delivered proposals — it recomputes the id from the
    /// proposal payload and binds the multisig address and chain before
    /// signing. Reserve this method for ids from trusted sources (on-chain
    /// reads, locally constructed proposals).
    pub async fn confirm(&self, wallet: &dyn WalletExecutor, id: Felt) -> Result<Tx> {
        wallet.execute(vec![self.populate_confirm(id)]).await
    }

    /// Confirm a coordination proposal, validating it before signing.
    ///
    /// Rejects the confirmation when the proposal's `transaction_id` does not
    /// recompute from `calls`/`salt`, when the proposal targets a different
    /// multisig contract than this handle, when the proposal was created for a
    /// different chain, or when the signing wallet is bound to a different
    /// chain than this handle. This is the safe entry point for acting on
    /// coordinator-delivered proposals.
    pub async fn confirm_proposal(
        &self,
        wallet: &dyn WalletExecutor,
        proposal: &MultisigProposal,
    ) -> Result<Tx> {
        proposal.validate_transaction_id()?;
        if proposal.multisig != self.address {
            return Err(KmsError::MultisigError(format!(
                "proposal targets multisig {} but this handle is {}",
                proposal.multisig.to_hex(),
                self.address.to_hex()
            )));
        }
        if proposal.chain_id != self.chain_id {
            return Err(KmsError::MultisigError(format!(
                "proposal was created for chain {} but this handle is on {}",
                proposal.chain_id, self.chain_id
            )));
        }
        let wallet_chain = wallet.chain_id();
        if wallet_chain != self.chain_id {
            return Err(KmsError::MultisigError(format!(
                "wallet chain {} does not match multisig chain {}",
                wallet_chain, self.chain_id
            )));
        }
        self.confirm(wallet, proposal.transaction_id).await
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
            ChainId::Sepolia,
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
            ChainId::Sepolia,
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
                MultisigSignerNotice::new(
                    address(1),
                    ChainId::Sepolia,
                    proposal.transaction_id,
                    address(3),
                ),
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
            ChainId::Sepolia,
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
            ChainId::Sepolia,
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
    fn test_incoming_message_validation() {
        let proposal = MultisigProposal::new(
            address(1),
            ChainId::Sepolia,
            vec![call()],
            Felt::from(99u64),
            address(2),
            None,
        );
        let topic = proposal.topic();
        let message = MultisigCoordinationMessage::Proposal(proposal.clone());

        // Consistent proposal passes.
        validate_incoming_message(&topic, &message).unwrap();

        // Cross-topic replay/misrouting is rejected.
        let other_topic = MultisigTopic {
            multisig: address(9),
            chain_id: topic.chain_id,
            transaction_id: topic.transaction_id,
        };
        assert!(validate_incoming_message(&other_topic, &message).is_err());

        // Same multisig and id on another chain is a different topic.
        let other_chain_topic = MultisigTopic {
            multisig: topic.multisig,
            chain_id: ChainId::Mainnet,
            transaction_id: topic.transaction_id,
        };
        assert!(validate_incoming_message(&other_chain_topic, &message).is_err());

        // Forged transaction id (id not recomputing from calls/salt) is rejected.
        let mut forged = proposal;
        forged.transaction_id = Felt::from(1u64);
        let forged_topic = forged.topic();
        let forged_message = MultisigCoordinationMessage::Proposal(forged);
        assert!(validate_incoming_message(&forged_topic, &forged_message).is_err());
    }

    struct RecordingExecutor {
        network: krusty_kms_common::network::NetworkPreset,
        wallet_address: Address,
        chain_id: ChainId,
        executed: std::sync::Mutex<Vec<Vec<Call>>>,
    }

    impl RecordingExecutor {
        fn sepolia(wallet_address: Address) -> Self {
            Self {
                network: krusty_kms_common::network::NetworkPreset::sepolia(),
                wallet_address,
                chain_id: ChainId::Sepolia,
                executed: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn executed_count(&self) -> usize {
            self.executed.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl WalletExecutor for RecordingExecutor {
        async fn execute(&self, calls: Vec<Call>) -> Result<Tx> {
            self.executed.lock().unwrap().push(calls);
            Err(KmsError::CryptoError("recorded".to_string()))
        }

        async fn estimate_fee(
            &self,
            _calls: Vec<Call>,
        ) -> Result<starknet_rust::core::types::FeeEstimate> {
            unreachable!("confirm_proposal tests never estimate fees")
        }

        fn address(&self) -> &Address {
            &self.wallet_address
        }

        fn chain_id(&self) -> ChainId {
            self.chain_id
        }

        fn network(&self) -> &krusty_kms_common::network::NetworkPreset {
            &self.network
        }

        async fn is_deployed(&self) -> Result<bool> {
            Ok(true)
        }
    }

    fn test_multisig_handle(address_value: u64) -> Multisig {
        let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
            Url::parse("http://127.0.0.1:0").unwrap(),
        )));
        Multisig::new(provider, address(address_value), ChainId::Sepolia)
    }

    #[tokio::test]
    async fn test_confirm_proposal_reaches_executor_with_recomputed_id() {
        let multisig = test_multisig_handle(1);
        let executor = RecordingExecutor::sepolia(address(2));
        let proposal = multisig.proposal(vec![call()], Felt::from(99u64), address(2), None);

        let result = multisig.confirm_proposal(&executor, &proposal).await;
        assert!(matches!(result, Err(KmsError::CryptoError(_))));
        let executed = executor.executed.lock().unwrap();
        assert_eq!(
            executed.as_slice(),
            &[vec![multisig.populate_confirm(proposal.transaction_id)]]
        );
    }

    #[tokio::test]
    async fn test_confirm_proposal_rejects_forged_transaction_id() {
        let multisig = test_multisig_handle(1);
        let executor = RecordingExecutor::sepolia(address(2));
        let mut forged = multisig.proposal(vec![call()], Felt::from(99u64), address(2), None);
        forged.transaction_id = Felt::from(1u64);

        assert!(matches!(
            multisig.confirm_proposal(&executor, &forged).await,
            Err(KmsError::MultisigError(_))
        ));
        assert_eq!(executor.executed_count(), 0);
    }

    #[tokio::test]
    async fn test_confirm_proposal_rejects_foreign_multisig() {
        let multisig = test_multisig_handle(1);
        let executor = RecordingExecutor::sepolia(address(2));
        let foreign = MultisigProposal::new(
            address(77),
            ChainId::Sepolia,
            vec![call()],
            Felt::from(99u64),
            address(2),
            None,
        );

        assert!(matches!(
            multisig.confirm_proposal(&executor, &foreign).await,
            Err(KmsError::MultisigError(_))
        ));
        assert_eq!(executor.executed_count(), 0);
    }

    #[tokio::test]
    async fn test_confirm_proposal_rejects_wallet_on_wrong_chain() {
        // The transaction id hash binds calls and salt but no chain, so a
        // replayed proposal must be stopped at the chain check instead.
        let multisig = test_multisig_handle(1);
        let mut executor = RecordingExecutor::sepolia(address(2));
        executor.chain_id = ChainId::Mainnet;
        let proposal = multisig.proposal(vec![call()], Felt::from(99u64), address(2), None);

        assert!(matches!(
            multisig.confirm_proposal(&executor, &proposal).await,
            Err(KmsError::MultisigError(_))
        ));
        assert_eq!(executor.executed_count(), 0);
    }

    #[tokio::test]
    async fn test_confirm_proposal_rejects_proposal_from_wrong_chain() {
        // A proposal created for mainnet replayed through the coordinator to
        // a Sepolia handle must be rejected even when address and id match.
        let multisig = test_multisig_handle(1);
        let executor = RecordingExecutor::sepolia(address(2));
        let mut proposal = multisig.proposal(vec![call()], Felt::from(99u64), address(2), None);
        proposal.chain_id = ChainId::Mainnet;

        assert!(matches!(
            multisig.confirm_proposal(&executor, &proposal).await,
            Err(KmsError::MultisigError(_))
        ));
        assert_eq!(executor.executed_count(), 0);
    }

    #[test]
    fn test_http_coordinator_preserves_base_path() {
        // Fictional host: use unchecked (from_url resolves DNS).
        let coordinator =
            HttpMultisigCoordinator::from_url_unchecked("https://coordinator.example/api").unwrap();
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
        assert!(HttpMultisigCoordinator::from_url("http://10.0.0.1/").is_err());
        assert!(HttpMultisigCoordinator::from_url("http://192.168.1.1/").is_err());
        assert!(HttpMultisigCoordinator::from_url("http://172.16.0.1/").is_err());
        assert!(HttpMultisigCoordinator::from_url("http://[fc00::1]/").is_err());
        assert!(HttpMultisigCoordinator::from_url("http://[fe80::1]/").is_err());
        assert!(HttpMultisigCoordinator::from_url("http://240.0.0.1/").is_err());
        // NAT64 / IPv4-translation prefixes embedding private IPv4 (10.0.0.1).
        assert!(HttpMultisigCoordinator::from_url("http://[64:ff9b:1::a00:1]/").is_err());
        assert!(HttpMultisigCoordinator::from_url("http://[64:ff9b::a00:1]/").is_err());
        // Public embedding via well-known NAT64 prefix remains allowed.
        assert!(HttpMultisigCoordinator::from_url("http://[64:ff9b::808:808]/").is_ok());
        assert!(HttpMultisigCoordinator::from_url_unchecked("http://127.0.0.1/").is_ok());
    }

    #[test]
    fn test_http_coordinator_rejects_non_public_ipv6_ranges() {
        // Deprecated site-local fec0::/10 (RFC 3879).
        assert!(HttpMultisigCoordinator::from_url("http://[fec0::1]/").is_err());
        assert!(HttpMultisigCoordinator::from_url("http://[feff:ffff::1]/").is_err());
        // Legacy transition formats embedding private IPv4 (10.0.0.1).
        assert!(HttpMultisigCoordinator::from_url("http://[2002:a00:1::1]/").is_err());
        assert!(HttpMultisigCoordinator::from_url("http://[::a00:1]/").is_err());
        // Equivalent public embeddings (8.8.8.8) stay allowed.
        assert!(HttpMultisigCoordinator::from_url("http://[2002:808:808::1]/").is_ok());
        assert!(HttpMultisigCoordinator::from_url("http://[::808:808]/").is_ok());
        // Global unicast outside the blocked ranges is unaffected.
        assert!(HttpMultisigCoordinator::from_url("http://[2606:4700::1111]/").is_ok());
    }

    #[test]
    fn test_nats_subject_is_deterministic() {
        let topic = MultisigTopic {
            multisig: address(1),
            chain_id: ChainId::Sepolia,
            transaction_id: Felt::from(2u64),
        };

        assert_eq!(
            NatsMultisigCoordinator::subject_for("krusty.multisig.", &topic),
            "krusty.multisig.SN_SEPOLIA.0000000000000000000000000000000000000000000000000000000000000001.0000000000000000000000000000000000000000000000000000000000000002"
        );
    }
}
