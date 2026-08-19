//! Hostile-RPC regression tests for the client submit paths.
//!
//! The canned JSON-RPC harness lives in `common/` so this file stays about the
//! properties under test rather than the plumbing.

mod common;

use common::{assert_fee_was_refused, assert_tip_was_pinned, dummy_call, hostile_context};
use krusty_kms::{OpenZeppelinAccount, SaltPolicy};
use krusty_kms_client::{FeeBounds, Wallet, ONE_STRK_FRI};
use krusty_kms_common::address::Address;
use krusty_kms_common::chain::ChainId;
use starknet_rust::signers::SigningKey;
use starknet_types_core::felt::Felt;
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[tokio::test]
async fn hostile_gas_price_is_refused_before_signing() {
    let (state, provider, network) = hostile_context().await;

    let wallet = Wallet::from_private_key_at_address(
        provider,
        Felt::from_hex_unchecked("0x1234"),
        Address::from(Felt::from_hex_unchecked("0xabc")),
        ChainId::Sepolia,
        network,
    )
    .with_fee_bounds(FeeBounds::default().with_max_fee_fri(ONE_STRK_FRI));

    let result = wallet.execute(vec![dummy_call()]).await;
    assert_fee_was_refused(&state, &result);
}

#[tokio::test]
async fn hostile_gas_price_is_refused_before_signing_a_deployment() {
    let (state, provider, network) = hostile_context().await;

    let signing_key = SigningKey::from_secret_scalar(
        starknet_rust::core::types::Felt::from_hex_unchecked("0x1234"),
    );
    let account_class = OpenZeppelinAccount::from_class_hash(Felt::from_hex_unchecked("0xdef"));

    let result = krusty_kms_client::deploy_oz_account_with_bounds(
        provider,
        &signing_key,
        &account_class,
        SaltPolicy::Zero,
        ChainId::Sepolia,
        network,
        &FeeBounds::default().with_max_fee_fri(ONE_STRK_FRI),
    )
    .await;
    assert_fee_was_refused(&state, &result);
}

/// A transaction must be tracked by the hash we signed, not the one the
/// endpoint echoes back.
#[tokio::test]
async fn submitted_transaction_is_tracked_by_the_locally_computed_hash() {
    let (state, provider, network) = hostile_context().await;

    // Ceiling lifted so we reach submission; this test is about the hash.
    let wallet = Wallet::from_private_key_at_address(
        provider,
        Felt::from_hex_unchecked("0x1234"),
        Address::from(Felt::from_hex_unchecked("0xabc")),
        ChainId::Sepolia,
        network,
    )
    .with_fee_bounds(FeeBounds::default().with_max_fee_fri(u128::MAX));

    let tx = wallet
        .execute(vec![dummy_call()])
        .await
        .expect("submission should succeed once the ceiling allows it");

    assert_eq!(
        state.submits.load(Ordering::SeqCst),
        1,
        "expected one submission"
    );
    assert_tip_was_pinned(&state);
    // Equality against an independent oracle, not `!= 0xdead`. A merely
    // *different* hash would satisfy an inequality: flipping
    // `transaction_hash(false)` to `true` yields the query-only variant, which
    // no broadcast transaction ever has, so every `Tx::wait` would poll until
    // timeout — and `assert_ne!` would still pass.
    assert_eq!(
        tx.hash(),
        expected_invoke_hash(),
        "tracked hash is not the one this transaction was signed with"
    );
}

#[tokio::test]
async fn submitted_deployment_pins_tip_and_tracks_the_local_hash() {
    let (state, provider, network) = hostile_context().await;
    let signing_key = SigningKey::from_secret_scalar(
        starknet_rust::core::types::Felt::from_hex_unchecked("0x1234"),
    );
    let account_class = OpenZeppelinAccount::from_class_hash(Felt::from_hex_unchecked("0xdef"));

    let result = krusty_kms_client::deploy_oz_account_with_bounds(
        provider,
        &signing_key,
        &account_class,
        SaltPolicy::Zero,
        ChainId::Sepolia,
        network,
        &FeeBounds::default().with_max_fee_fri(u128::MAX),
    )
    .await
    .expect("approved deployment should submit");
    let tx = result.tx.expect("new account should have a deployment tx");

    assert_eq!(
        state.submits.load(Ordering::SeqCst),
        1,
        "expected one submission"
    );
    assert_tip_was_pinned(&state);
    // Equality against an independent oracle, not `!= 0xdead`. A merely
    // *different* hash would satisfy an inequality: flipping
    // `transaction_hash(false)` to `true` yields the query-only variant, which
    // no broadcast transaction ever has, so every `Tx::wait` would poll until
    // timeout — and `assert_ne!` would still pass.
    assert_eq!(
        tx.hash(),
        expected_deploy_hash(&signing_key, &account_class),
        "tracked hash is not the one this deployment was signed with"
    );
}

/// Bounds the canned estimate resolves to under the default 1.5x multipliers.
fn expected_resource_bounds() -> [krusty_kms::tx_hash::ResourceBounds; 3] {
    use krusty_kms::tx_hash::ResourceBounds;
    let amount = |v: u64| (v as f64 * 1.5) as u64;
    let price = |v: u128| (v as f64 * 1.5) as u128;
    [
        ResourceBounds {
            max_amount: amount(0x100),
            max_price_per_unit: price(0x100),
        },
        ResourceBounds {
            max_amount: amount(0x100000),
            max_price_per_unit: price(0x38d7ea4c68000),
        },
        ResourceBounds {
            max_amount: amount(0x100),
            max_price_per_unit: price(0x100),
        },
    ]
}

fn to_rs(felt: Felt) -> starknet_rust::core::types::Felt {
    starknet_rust::core::types::Felt::from_bytes_be(&felt.to_bytes_be())
}

/// The invoke-v3 hash the submitted transaction must carry, computed by the KMS
/// crate rather than by the submission path under test.
fn expected_invoke_hash() -> starknet_rust::core::types::Felt {
    use krusty_kms::tx_hash::DaMode;

    let call = dummy_call();
    // `__execute__` multicall layout: [n, to, selector, data_len, ...data]
    let calldata = vec![
        Felt::ONE,
        Felt::from_bytes_be(&call.to.to_bytes_be()),
        Felt::from_bytes_be(&call.selector.to_bytes_be()),
        Felt::ZERO,
    ];
    let [l1_gas, l2_gas, l1_data_gas] = expected_resource_bounds();

    to_rs(krusty_kms::compute_invoke_v3_hash(
        &Felt::from_hex_unchecked("0xabc"),
        &calldata,
        &ChainId::Sepolia.as_felt(),
        &Felt::ZERO,
        &[],
        0,
        &l1_gas,
        &l2_gas,
        &l1_data_gas,
        &[],
        DaMode::L1,
        DaMode::L1,
    ))
}

/// The deploy-account-v3 hash the submitted deployment must carry.
fn expected_deploy_hash(
    signing_key: &SigningKey,
    account_class: &OpenZeppelinAccount,
) -> starknet_rust::core::types::Felt {
    use krusty_kms::tx_hash::DaMode;

    let public_key = Felt::from_bytes_be(&signing_key.verifying_key().scalar().to_bytes_be());
    let descriptor = account_class
        .deployment_descriptor(&public_key, SaltPolicy::Zero)
        .expect("descriptor");
    let [l1_gas, l2_gas, l1_data_gas] = expected_resource_bounds();

    to_rs(krusty_kms::compute_deploy_account_v3_hash(
        &descriptor.address,
        &descriptor.class_hash,
        &[public_key],
        &descriptor.salt,
        &ChainId::Sepolia.as_felt(),
        &Felt::ZERO,
        0,
        &l1_gas,
        &l2_gas,
        &l1_data_gas,
        &[],
        DaMode::L1,
        DaMode::L1,
    ))
}

/// A host must be able to act on `fee approval required` without rebuilding the
/// wallet. The shape it will actually hold is an `Arc<Wallet>` shared across a
/// session, and every constructor moves the `SigningKey` in — so rebuilding
/// would mean retaining key material solely to approve a fee.
#[tokio::test]
async fn approval_can_be_applied_to_a_retry_without_rebuilding_the_wallet() {
    let (state, provider, network) = hostile_context().await;

    // Shared, so only `&self` is reachable from here on.
    let wallet = Arc::new(Wallet::from_private_key_at_address(
        provider,
        Felt::from_hex_unchecked("0x1234"),
        Address::from(Felt::from_hex_unchecked("0xabc")),
        ChainId::Sepolia,
        network,
    ));

    let err = match wallet.execute(vec![dummy_call()]).await {
        Ok(_) => panic!("an unapproved fee must not be signed"),
        Err(e) => e,
    };
    assert!(
        krusty_kms_common::is_fee_approval_required(&err),
        "hosts route on this predicate, not on the message text: {err}"
    );
    assert_eq!(
        state.submits.load(Ordering::SeqCst),
        0,
        "nothing may be sent before approval"
    );

    // The user approves the reported amount. No &mut, no rebuild, no key.
    let approved = FeeBounds::default().with_max_fee_fri(10_000 * ONE_STRK_FRI);
    assert!(
        wallet
            .execute_with_bounds(vec![dummy_call()], &approved)
            .await
            .is_ok(),
        "the approved retry must submit"
    );
    assert_eq!(
        state.submits.load(Ordering::SeqCst),
        1,
        "expected exactly one submission after approval"
    );
}

/// The whole approval loop must complete behind `&dyn WalletExecutor` — the
/// type the transfer, staking, multisig and transaction-builder APIs accept.
/// After that type erasure the concrete `Wallet` methods are unreachable, and
/// rebuilding would mean retaining the moved signing key just to approve a fee.
#[tokio::test]
async fn approval_loop_completes_through_the_executor_trait() {
    use krusty_kms_client::{fee_approval_required_fri, WalletExecutor};

    let (state, provider, network) = hostile_context().await;
    let wallet = Wallet::from_private_key_at_address(
        provider,
        Felt::from_hex_unchecked("0x1234"),
        Address::from(Felt::from_hex_unchecked("0xabc")),
        ChainId::Sepolia,
        network,
    );
    let executor: &dyn WalletExecutor = &wallet;

    // 1. Refused, with nothing sent.
    let err = match executor.execute(vec![dummy_call()]).await {
        Ok(_) => panic!("an unapproved fee must not be signed"),
        Err(e) => e,
    };
    assert_eq!(state.submits.load(Ordering::SeqCst), 0);

    // 2. The figure to show the user, as a number rather than scraped prose.
    let total = fee_approval_required_fri(&err).expect("amount must be recoverable");

    // 3. Approve exactly that and retry — through the trait, no rebuild.
    assert!(
        executor
            .execute_with_bounds(
                vec![dummy_call()],
                &FeeBounds::default().with_max_fee_fri(total)
            )
            .await
            .is_ok(),
        "approving the reported amount must let the retry through"
    );
    assert_eq!(state.submits.load(Ordering::SeqCst), 1);
}

/// The approval loop must work through `TxBuilder`, the advertised way to
/// batch calls. A refusal must not destroy the transaction it refused: the
/// caller needs those same calls to resubmit once the user consents.
#[tokio::test]
async fn approval_loop_completes_through_the_transaction_builder() {
    use krusty_kms_client::fee_approval_required_fri;

    let (state, provider, network) = hostile_context().await;
    let wallet = Wallet::from_private_key_at_address(
        provider,
        Felt::from_hex_unchecked("0x1234"),
        Address::from(Felt::from_hex_unchecked("0xabc")),
        ChainId::Sepolia,
        network,
    );

    let builder = wallet.tx().add(dummy_call()).add(dummy_call());

    let err = match builder.send().await {
        Ok(_) => panic!("an unapproved fee must not be signed"),
        Err(e) => e,
    };
    assert_eq!(state.submits.load(Ordering::SeqCst), 0);
    let total = fee_approval_required_fri(&err).expect("amount must be recoverable");

    // The builder survived the refusal, so the same batch can be resubmitted.
    assert!(
        builder
            .send_with_bounds(&FeeBounds::default().with_max_fee_fri(total))
            .await
            .is_ok(),
        "the approved retry must submit the same calls"
    );
    assert_eq!(state.submits.load(Ordering::SeqCst), 1);
    assert_eq!(builder.calls().len(), 2, "the batch must be intact");
}

/// The convenience wrappers (`Erc20`, `Staking`, multisig) borrow a
/// `&dyn WalletExecutor` and take no bounds argument, so an owner must be able
/// to raise the ceiling in place rather than rebuild around the moved key.
#[tokio::test]
async fn approved_bounds_can_be_applied_in_place() {
    use krusty_kms_client::fee_approval_required_fri;

    let (state, provider, network) = hostile_context().await;
    let mut wallet = Wallet::from_private_key_at_address(
        provider,
        Felt::from_hex_unchecked("0x1234"),
        Address::from(Felt::from_hex_unchecked("0xabc")),
        ChainId::Sepolia,
        network,
    );

    let err = match wallet.execute(vec![dummy_call()]).await {
        Ok(_) => panic!("an unapproved fee must not be signed"),
        Err(e) => e,
    };
    let total = fee_approval_required_fri(&err).expect("amount must be recoverable");

    wallet.set_fee_bounds(FeeBounds::default().with_max_fee_fri(total));

    assert!(
        wallet.execute(vec![dummy_call()]).await.is_ok(),
        "the same entry point must succeed once bounds are approved"
    );
    assert_eq!(state.submits.load(Ordering::SeqCst), 1);
}
