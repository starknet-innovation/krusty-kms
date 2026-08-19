//! The fee-approval loop, exercised from every client entry point.
//!
//! A refused submission must be completable: the caller recovers the resolved
//! amount as a number, approves it, and resubmits the same calls — without
//! rebuilding the wallet around the moved signing key.

mod common;

use common::{dummy_call, hostile_context};
use krusty_kms_client::{
    fee_approval_required_fri, FeeBounds, Wallet, WalletExecutor, ONE_STRK_FRI,
};
use krusty_kms_common::address::Address;
use krusty_kms_common::chain::ChainId;
use starknet_types_core::felt::Felt;
use std::sync::atomic::Ordering;
use std::sync::Arc;

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
