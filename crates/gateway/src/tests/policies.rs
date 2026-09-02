//! Operation retention and class-hash allowlist policies.

use super::{derivation_request, gateway_with_retention, nostr_sign_request, TestClock};
use crate::account_class::{enforce_class_hash_allowlist, resolve_account_class};
use crate::{DeployExecution, OperationRetentionError, OperationRetentionPolicy};
use krusty_kms::{AccountClass, ArgentAccount, OpenZeppelinAccount};
use krusty_kms_common::ChainId;
use krusty_kms_domain::{
    AccountClassKind, AccountClassSpec, FeltHex, GatewayErrorCode, OperationLookupResult,
    OperationState, OperationStatus,
};
use starknet_types_core::felt::Felt;

#[test]
fn operation_retention_policy_rejects_zero_values() {
    assert_eq!(
        OperationRetentionPolicy::new(0, 1),
        Err(OperationRetentionError::ZeroTtl)
    );
    assert_eq!(
        OperationRetentionPolicy::new(1, 0),
        Err(OperationRetentionError::ZeroMaxEntries)
    );
}

#[tokio::test]
async fn operation_status_evicts_entries_past_ttl() {
    let clock = TestClock::default();
    clock.set(1_000);
    let gateway = gateway_with_retention(
        clock,
        DeployExecution::AlreadyDeployed,
        OperationRetentionPolicy::new(100, 8).unwrap(),
    );

    let response = gateway.derive_account(derivation_request()).await.unwrap();
    assert_eq!(
        gateway.operation_status(&response.operation.id).await,
        OperationLookupResult::Found {
            operation: response.operation.clone()
        }
    );

    gateway.clock.set(1_101);
    assert_eq!(
        gateway.operation_status(&response.operation.id).await,
        OperationLookupResult::Found {
            operation: OperationStatus {
                id: response.operation.id.clone(),
                kind: response.operation.kind,
                state: OperationState::Expired,
                provenance: response.operation.provenance.clone(),
            }
        }
    );
}

#[tokio::test]
async fn operation_status_evicts_oldest_entries_when_capacity_is_exceeded() {
    let clock = TestClock::default();
    let gateway = gateway_with_retention(
        clock,
        DeployExecution::AlreadyDeployed,
        OperationRetentionPolicy::new(60_000, 2).unwrap(),
    );

    let first = gateway.derive_account(derivation_request()).await.unwrap();
    let second = gateway
        .check_deployment(derivation_request())
        .await
        .unwrap();
    let third = gateway.sign(nostr_sign_request()).await.unwrap();

    assert_eq!(
        gateway.operation_status(&first.operation.id).await,
        OperationLookupResult::NotFound {
            operation_id: first.operation.id.clone()
        }
    );
    assert_eq!(
        gateway.operation_status(&second.operation.id).await,
        OperationLookupResult::Found {
            operation: second.operation.clone()
        }
    );
    assert_eq!(
        gateway.operation_status(&third.operation.id).await,
        OperationLookupResult::Found {
            operation: third.operation.clone()
        }
    );
}

#[test]
fn class_hash_allowlist_accepts_known_open_zeppelin_hash() {
    let known = OpenZeppelinAccount::latest(ChainId::Sepolia)
        .unwrap()
        .class_hash();
    assert!(enforce_class_hash_allowlist(
        known,
        AccountClassKind::OpenZeppelin,
        ChainId::Sepolia,
        false,
    )
    .is_ok());
}

#[test]
fn class_hash_allowlist_rejects_unknown_hash() {
    let err = enforce_class_hash_allowlist(
        Felt::from_hex("0xdeadbeef").unwrap(),
        AccountClassKind::OpenZeppelin,
        ChainId::Sepolia,
        false,
    )
    .expect_err("unknown hash must be rejected");
    assert_eq!(err.code, GatewayErrorCode::InvalidClassHash);
    assert!(
        err.message
            .as_deref()
            .unwrap_or("")
            .contains("allow_unlisted_class_hash=true"),
        "unexpected message: {:?}",
        err.message
    );
}

#[test]
fn class_hash_allowlist_override_allows_unknown_hash() {
    assert!(enforce_class_hash_allowlist(
        Felt::from_hex("0xdeadbeef").unwrap(),
        AccountClassKind::OpenZeppelin,
        ChainId::Sepolia,
        true,
    )
    .is_ok());
}

#[test]
fn class_hash_allowlist_accepts_known_argent_versions() {
    for hash in ArgentAccount::known_class_hashes() {
        assert!(
            enforce_class_hash_allowlist(hash, AccountClassKind::Argent, ChainId::Sepolia, false,)
                .is_ok(),
            "expected known Argent hash {hash:#x} to be allowed"
        );
    }
}

#[test]
fn argent_unlisted_class_hash_is_rejected_even_with_override() {
    // The allowlist override cannot supply the constructor layout, and
    // guessing it derives an undeployable address, so an unrecognised Argent
    // class must still be refused.
    let resolved = resolve_account_class(
        &AccountClassSpec {
            kind: AccountClassKind::Argent,
            class_hash: Some(FeltHex::parse("0xdeadbeef").unwrap()),
            source_label: None,
            allow_unlisted_class_hash: true,
        },
        ChainId::Sepolia,
    );
    let Err(err) = resolved else {
        panic!("unknown Argent class hash must be rejected");
    };
    assert_eq!(err.code, GatewayErrorCode::InvalidClassHash);
}
