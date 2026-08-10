//! End-to-end gateway flow tests: derive, deploy, sign, and snapshot caching.

use super::{
    derivation_request, gateway, nostr_sign_request, raw_nostr_sign_request, snapshot_request,
    stark_sign_request, TestClock,
};
use crate::snapshot::MAX_SNAPSHOT_TTL_MS;
use crate::DeployExecution;
use krusty_kms_common::ChainId;
use krusty_kms_domain::{
    CachePolicy, CacheStatus, DeployAccountRequest, DeployMode, FeltHex, GatewayErrorCode,
    OperationKind, OperationLookupResult, OperationState, QueryMode, SignResult,
};
use std::sync::atomic::Ordering;

#[tokio::test]
async fn derive_account_returns_descriptor_and_final_status() {
    let clock = TestClock::default();
    let gateway = gateway(clock, DeployExecution::AlreadyDeployed);

    let response = gateway.derive_account(derivation_request()).await.unwrap();

    assert_eq!(response.operation.kind, OperationKind::DeriveAccount);
    assert_eq!(response.operation.state, OperationState::Completed);
    assert_eq!(response.value.provenance.chain_id, ChainId::Sepolia);
    assert!(response.value.address.as_str().starts_with("0x"));
    assert_eq!(response.value.constructor_calldata.len(), 1);
}

#[tokio::test]
async fn deploy_submit_only_maps_to_submitted_state() {
    let clock = TestClock::default();
    let tx_hash = FeltHex::parse("0xdead").unwrap();
    let gateway = gateway(
        clock,
        DeployExecution::Submitted {
            tx_hash: tx_hash.clone(),
        },
    );

    let response = gateway
        .deploy_account(DeployAccountRequest {
            derivation: derivation_request(),
            mode: DeployMode::SubmitOnly,
        })
        .await
        .unwrap();

    assert_eq!(
        response.operation.state,
        OperationState::Submitted {
            tx_hash: tx_hash.clone()
        }
    );
    assert_eq!(
        response.value.deployment,
        krusty_kms_domain::DeploymentState::Deploying { tx_hash }
    );

    let stored = gateway.operation_status(&response.operation.id).await;
    assert_eq!(
        stored,
        OperationLookupResult::Found {
            operation: response.operation.clone()
        }
    );
}

#[tokio::test]
async fn query_account_snapshot_uses_stale_cache_for_background_mode() {
    let clock = TestClock::default();
    clock.set(1_000);
    let gateway = gateway(clock, DeployExecution::AlreadyDeployed);

    let first = gateway
        .query_account_snapshot(snapshot_request(QueryMode::ActiveView))
        .await
        .unwrap();
    assert_eq!(first.value.cache.status, CacheStatus::Miss);

    gateway.clock.set(2_500);
    let stale = gateway
        .query_account_snapshot(snapshot_request(QueryMode::BackgroundView))
        .await
        .unwrap();
    assert_eq!(stale.value.cache.status, CacheStatus::Stale);
    assert_eq!(stale.value.cache.generated_at_ms, 1_000);

    let checks_after_stale = gateway.backend.deployment_checks.load(Ordering::Relaxed);
    assert_eq!(checks_after_stale, 1);

    let refreshed = gateway
        .query_account_snapshot(snapshot_request(QueryMode::ActiveView))
        .await
        .unwrap();
    assert_eq!(refreshed.value.cache.status, CacheStatus::Miss);
    assert_eq!(gateway.backend.deployment_checks.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn derive_account_rejects_wrong_coin_type() {
    let clock = TestClock::default();
    let gateway = gateway(clock, DeployExecution::AlreadyDeployed);
    let mut request = derivation_request();
    request.path.coin_type = 5454;

    let error = gateway.derive_account(request).await.unwrap_err();
    assert_eq!(error.code, GatewayErrorCode::InvalidDerivationPath);
    assert!(!error.retryable);
}

#[tokio::test]
async fn operation_ids_are_unique_unpredictable_and_prefixed() {
    let clock = TestClock::default();
    let gateway = gateway(clock, DeployExecution::AlreadyDeployed);

    let first = gateway.derive_account(derivation_request()).await.unwrap();
    let second = gateway.derive_account(derivation_request()).await.unwrap();

    let first_id = first.operation.id.as_str();
    let second_id = second.operation.id.as_str();

    assert!(first_id.starts_with("derive-"));
    assert!(second_id.starts_with("derive-"));
    // 128 bits of entropy: no sequential `-1`/`-2` suffixes to enumerate.
    assert_eq!(first_id.len(), "derive-".len() + 32);
    assert_ne!(first_id, second_id);
}

#[tokio::test]
async fn deploy_rejects_excessive_wait_timeout() {
    let clock = TestClock::default();
    let gateway = gateway(clock, DeployExecution::AlreadyDeployed);
    let request = DeployAccountRequest {
        derivation: derivation_request(),
        mode: DeployMode::WaitForAcceptance(krusty_kms_domain::WaitPolicy {
            poll_interval_ms: 500,
            timeout_ms: u64::MAX,
        }),
    };

    let error = gateway.deploy_account(request).await.unwrap_err();
    assert_eq!(error.code, GatewayErrorCode::InvalidWaitPolicy);
    assert!(!error.retryable);
}

#[tokio::test]
async fn snapshot_ttl_is_clamped_to_server_ceiling() {
    let clock = TestClock::default();
    clock.set(1_000);
    let gateway = gateway(clock, DeployExecution::AlreadyDeployed);

    let mut request = snapshot_request(QueryMode::ActiveView);
    request.cache_policy = CachePolicy::new(u64::MAX, u64::MAX, 8).unwrap();

    let first = gateway
        .query_account_snapshot(request.clone())
        .await
        .unwrap();
    assert_eq!(first.value.cache.status, CacheStatus::Miss);

    // Age the entry past the server TTL ceiling: despite the request's
    // u64::MAX ttl, the entry must not come back as a fresh Hit.
    gateway.clock.set(1_000 + MAX_SNAPSHOT_TTL_MS + 1);
    let second = gateway.query_account_snapshot(request).await.unwrap();
    assert_eq!(second.value.cache.status, CacheStatus::Miss);
    assert_eq!(
        gateway.backend.deployment_checks.load(Ordering::Relaxed),
        2,
        "clamped TTL must force a re-fetch instead of a fresh Hit"
    );
}

#[tokio::test]
async fn sign_returns_nostr_signature_and_tracks_completion() {
    let clock = TestClock::default();
    let gateway = gateway(clock, DeployExecution::AlreadyDeployed);

    let response = gateway.sign(nostr_sign_request()).await.unwrap();

    assert_eq!(response.operation.kind, OperationKind::Sign);
    assert_eq!(response.operation.state, OperationState::Completed);

    match response.value {
        SignResult::NostrBip340 {
            public_key,
            signature,
        } => {
            assert_eq!(public_key.as_str().len(), 64);
            assert_eq!(signature.as_str().len(), 128);
        }
        other => panic!("unexpected sign result: {other:?}"),
    }
}

#[tokio::test]
async fn sign_supports_stark_hash_domains_with_chain_provenance() {
    let clock = TestClock::default();
    let gateway = gateway(clock, DeployExecution::AlreadyDeployed);
    let response = gateway.sign(stark_sign_request()).await.unwrap();

    assert_eq!(response.operation.kind, OperationKind::Sign);
    assert_eq!(
        response.operation.provenance.as_ref().unwrap().chain_id,
        ChainId::Sepolia
    );

    match response.value {
        SignResult::StarkEcdsa {
            public_key,
            signature_r,
            signature_s,
        } => {
            assert!(public_key.as_str().starts_with("0x"));
            assert!(signature_r.as_str().starts_with("0x"));
            assert!(signature_s.as_str().starts_with("0x"));
        }
        other => panic!("unexpected sign result: {other:?}"),
    }
}

#[tokio::test]
async fn sign_supports_raw_nostr_messages() {
    let clock = TestClock::default();
    let gateway = gateway(clock, DeployExecution::AlreadyDeployed);

    let response = gateway.sign(raw_nostr_sign_request()).await.unwrap();

    match response.value {
        SignResult::NostrBip340 {
            public_key,
            signature,
        } => {
            assert_eq!(public_key.as_str().len(), 64);
            assert_eq!(signature.as_str().len(), 128);
        }
        other => panic!("unexpected sign result: {other:?}"),
    }
}
