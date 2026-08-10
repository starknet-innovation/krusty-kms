//! Coordinator transports: in-memory pub/sub, receive-side validation,
//! HTTP SSRF policy, and NATS subject construction.

use super::{address, call};
use crate::multisig::types::validate_incoming_message;
use crate::multisig::{
    HttpMultisigCoordinator, InMemoryMultisigCoordinator, MultisigCoordinationMessage,
    MultisigCoordinator, MultisigProposal, MultisigSignerNotice, MultisigTopic,
    NatsMultisigCoordinator,
};
use futures_util::StreamExt;
use krusty_kms_common::{ChainId, KmsError};
use starknet_types_core::felt::Felt;

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
