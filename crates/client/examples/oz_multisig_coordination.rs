use futures_util::StreamExt;
use krusty_kms_client::{
    hash_transaction_batch, InMemoryMultisigCoordinator, Multisig, MultisigCall,
    MultisigCoordinationMessage, MultisigCoordinator, MultisigExecutionNotice,
    MultisigSignerNotice, NatsMultisigCoordinator, SignedMultisigCoordinationMessage,
};
use krusty_kms_common::{Address, ChainId};
use starknet_rust::core::utils::get_selector_from_name;
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::signers::SigningKey;
use starknet_types_core::felt::Felt;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use url::Url;

fn demo_signing_key(secret: u64) -> SigningKey {
    SigningKey::from_secret_scalar(starknet_rust::core::types::Felt::from(secret))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(Url::parse(
        "http://127.0.0.1:5050",
    )?)));

    let multisig_address = Address::from_hex("0x401")?;
    let alice = Address::from_hex("0x101")?;
    let bob = Address::from_hex("0x202")?;
    let charlie = Address::from_hex("0x303")?;

    // Demo-only account keys. In production each signer's account key stays
    // inside their own wallet/KMS.
    let alice_key = demo_signing_key(0xA11CE);
    let bob_key = demo_signing_key(0xB0B);
    let charlie_key = demo_signing_key(0xC4A11E);

    let target = Address::from_hex("0x999")?;
    let add_number = get_selector_from_name("add_number")?;
    let call = MultisigCall::new(
        target,
        Felt::from_bytes_be(&add_number.to_bytes_be()),
        vec![Felt::from(42u64)],
    );

    // starknet-devnet reports SN_SEPOLIA as its chain id.
    let multisig = Multisig::new(provider, multisig_address, ChainId::Sepolia);
    let coordinator = InMemoryMultisigCoordinator::new();
    let salt = Felt::from(7u64);
    let proposal = multisig.proposal(
        vec![call],
        salt,
        alice,
        Some("Increase the target counter".to_string()),
    );

    proposal.validate_transaction_id()?;

    // Notices travel as signed envelopes so receivers can authenticate the
    // claimed proposer/signer/executor instead of trusting the coordinator.
    let signed_proposal = SignedMultisigCoordinationMessage::sign_with_stark_key(
        MultisigCoordinationMessage::Proposal(proposal.clone()),
        &alice_key,
    )?;

    if let Ok(nats_url) = std::env::var("NATS_URL") {
        let nats = NatsMultisigCoordinator::connect(&nats_url).await?;
        let mut subscription = nats.subscribe(&proposal.topic()).await?;
        nats.publish(signed_proposal.clone().into()).await?;

        let received = subscription
            .next()
            .await
            .transpose()?
            .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "NATS subscription closed"))?;
        assert_eq!(received.as_signed(), Some(&signed_proposal));
        println!("nats subject: {}", nats.subject(&proposal.topic()));
    }

    coordinator.publish(signed_proposal.clone().into()).await?;

    let submit_call = multisig.populate_submit_batch(&proposal.calls, proposal.salt);
    println!("submit selector: {:#x}", submit_call.selector);
    println!("submit calldata felts: {}", submit_call.calldata.len());

    let id = hash_transaction_batch(&proposal.calls, proposal.salt);
    assert_eq!(id, proposal.transaction_id);

    let bob_confirmation = SignedMultisigCoordinationMessage::sign_with_stark_key(
        MultisigCoordinationMessage::Confirmation(MultisigSignerNotice::new(
            multisig_address,
            ChainId::Sepolia,
            id,
            bob,
        )),
        &bob_key,
    )?;
    let charlie_confirmation = SignedMultisigCoordinationMessage::sign_with_stark_key(
        MultisigCoordinationMessage::Confirmation(MultisigSignerNotice::new(
            multisig_address,
            ChainId::Sepolia,
            id,
            charlie,
        )),
        &charlie_key,
    )?;
    let charlie_execution = SignedMultisigCoordinationMessage::sign_with_stark_key(
        MultisigCoordinationMessage::Execution(MultisigExecutionNotice::new(
            multisig_address,
            ChainId::Sepolia,
            id,
            charlie,
        )),
        &charlie_key,
    )?;

    coordinator.publish(bob_confirmation.clone().into()).await?;
    coordinator.publish(charlie_confirmation.into()).await?;
    coordinator.publish(charlie_execution.into()).await?;

    // Offline check against a known public key. Against a live chain, use
    // `multisig.verify_signed_message(&notice)` instead: it checks the claimed
    // actor against the on-chain signer set and the account's SNIP-6
    // `is_valid_signature` entrypoint.
    let bob_public_key = Felt::from_bytes_be(&bob_key.verifying_key().scalar().to_bytes_be());
    bob_confirmation.verify_with_stark_public_key(bob_public_key)?;
    println!("bob's confirmation notice verified offline");

    let messages = coordinator.messages(&proposal.topic()).await?;
    println!("coordinator messages: {}", messages.len());
    let signed_count = messages
        .iter()
        .filter(|envelope| envelope.as_signed().is_some())
        .count();
    println!("signed envelopes: {signed_count}");

    Ok(())
}
