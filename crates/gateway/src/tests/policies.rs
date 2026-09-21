//! Operation retention and class-hash allowlist policies.

use super::{derivation_request, gateway_with_retention, nostr_sign_request, TestClock};
use crate::account_class::{enforce_class_hash_allowlist, resolve_account_class};
use crate::{DeployExecution, OperationRetentionError, OperationRetentionPolicy};
use krusty_kms::{AccountClass, ArgentAccount, BraavosAccount, OpenZeppelinAccount};
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

#[test]
fn class_hash_allowlist_does_not_offer_the_override_for_argent() {
    // The override cannot supply an Argent constructor layout, so the rejection
    // message must not point callers at a flag that will not help them.
    let err = enforce_class_hash_allowlist(
        Felt::from_hex("0xdeadbeef").unwrap(),
        AccountClassKind::Argent,
        ChainId::Sepolia,
        false,
    )
    .expect_err("unknown Argent hash must be rejected");
    assert_eq!(err.code, GatewayErrorCode::InvalidClassHash);
    let message = err.message.as_deref().unwrap_or("");
    assert!(
        !message.contains("allow_unlisted_class_hash"),
        "Argent rejection must not advertise the override: {message}"
    );
}

#[test]
fn class_hash_allowlist_accepts_every_braavos_base_class() {
    for hash in BraavosAccount::deployment_class_hashes() {
        assert!(
            enforce_class_hash_allowlist(hash, AccountClassKind::Braavos, ChainId::Sepolia, false)
                .is_ok(),
            "expected Braavos base class {hash:#x} to be allowed"
        );
    }
}

#[test]
fn braavos_implementation_class_is_rejected_even_with_override() {
    // The class an upgraded Braavos account runs never fixed its address, so
    // deriving from it yields an address no deployment produces. Waiving the
    // allowlist cannot change that (issue #146).
    for hash in BraavosAccount::implementation_class_hashes() {
        for allow_unlisted in [false, true] {
            let resolved = resolve_account_class(
                &AccountClassSpec {
                    kind: AccountClassKind::Braavos,
                    class_hash: Some(FeltHex::parse(&format!("{hash:#x}")).unwrap()),
                    source_label: None,
                    allow_unlisted_class_hash: allow_unlisted,
                },
                ChainId::Sepolia,
            );
            let Err(err) = resolved else {
                panic!("Braavos implementation class {hash:#x} must be rejected");
            };
            assert_eq!(err.code, GatewayErrorCode::InvalidClassHash);
            let message = err.message.as_deref().unwrap_or("");
            assert!(
                message.contains("implementation class"),
                "unexpected message: {message}"
            );
            assert!(
                !message.contains("allow_unlisted_class_hash"),
                "must not advertise an override that cannot help: {message}"
            );
        }
    }
}

#[test]
fn braavos_unknown_class_hash_still_honours_the_override() {
    let spec = |allow_unlisted| AccountClassSpec {
        kind: AccountClassKind::Braavos,
        class_hash: Some(FeltHex::parse("0xdeadbeef").unwrap()),
        source_label: None,
        allow_unlisted_class_hash: allow_unlisted,
    };
    let err = resolve_account_class(&spec(false), ChainId::Sepolia)
        .err()
        .expect("unknown Braavos class hash must be rejected by default");
    assert_eq!(err.code, GatewayErrorCode::InvalidClassHash);
    assert!(err
        .message
        .as_deref()
        .unwrap_or("")
        .contains("allow_unlisted_class_hash=true"));

    let resolved = resolve_account_class(&spec(true), ChainId::Sepolia)
        .expect("override admits an unknown Braavos class hash");
    assert_eq!(resolved.class_hash(), Felt::from_hex("0xdeadbeef").unwrap());
}

#[test]
fn allowlist_refuses_braavos_implementation_classes_on_its_own() {
    // The check must hold for any caller of the allowlist, not only through
    // resolve_account_class, so the override cannot waive it here either.
    for hash in BraavosAccount::implementation_class_hashes() {
        for allow_unlisted in [false, true] {
            let err = enforce_class_hash_allowlist(
                hash,
                AccountClassKind::Braavos,
                ChainId::Sepolia,
                allow_unlisted,
            )
            .expect_err("implementation class must be refused");
            assert_eq!(err.code, GatewayErrorCode::InvalidClassHash);
        }
    }
    // The override still admits an unknown Braavos class hash.
    assert!(enforce_class_hash_allowlist(
        Felt::from_hex("0xdeadbeef").unwrap(),
        AccountClassKind::Braavos,
        ChainId::Sepolia,
        true,
    )
    .is_ok());
}
