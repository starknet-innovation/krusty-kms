use futures_util::StreamExt;
use krusty_kms_client::{
    hash_transaction_batch, InMemoryMultisigCoordinator, Multisig, MultisigCall,
    MultisigCoordinationMessage, MultisigCoordinator, MultisigExecutionNotice,
    MultisigSignerNotice, NatsMultisigCoordinator,
};
use krusty_kms_common::{Address, ChainId};
use starknet_rust::core::utils::get_selector_from_name;
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_types_core::felt::Felt;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use url::Url;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(Url::parse(
        "http://127.0.0.1:5050",
    )?)));

    let multisig_address = Address::from_hex("0x401")?;
    let alice = Address::from_hex("0x101")?;
    let bob = Address::from_hex("0x202")?;
    let charlie = Address::from_hex("0x303")?;

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

    if let Ok(nats_url) = std::env::var("NATS_URL") {
        let nats = NatsMultisigCoordinator::connect(&nats_url).await?;
        let mut subscription = nats.subscribe(&proposal.topic()).await?;
        nats.publish(MultisigCoordinationMessage::Proposal(proposal.clone()))
            .await?;

        let received = subscription
            .next()
            .await
            .transpose()?
            .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "NATS subscription closed"))?;
        assert_eq!(
            received,
            MultisigCoordinationMessage::Proposal(proposal.clone())
        );
        println!("nats subject: {}", nats.subject(&proposal.topic()));
    }

    coordinator
        .publish(MultisigCoordinationMessage::Proposal(proposal.clone()))
        .await?;

    let submit_call = multisig.populate_submit_batch(&proposal.calls, proposal.salt);
    println!("submit selector: {:#x}", submit_call.selector);
    println!("submit calldata felts: {}", submit_call.calldata.len());

    let id = hash_transaction_batch(&proposal.calls, proposal.salt);
    assert_eq!(id, proposal.transaction_id);

    coordinator
        .publish(MultisigCoordinationMessage::Confirmation(
            MultisigSignerNotice::new(multisig_address, ChainId::Sepolia, id, bob),
        ))
        .await?;
    coordinator
        .publish(MultisigCoordinationMessage::Confirmation(
            MultisigSignerNotice::new(multisig_address, ChainId::Sepolia, id, charlie),
        ))
        .await?;
    coordinator
        .publish(MultisigCoordinationMessage::Execution(
            MultisigExecutionNotice::new(multisig_address, ChainId::Sepolia, id, charlie),
        ))
        .await?;

    let messages = coordinator.messages(&proposal.topic()).await?;
    println!("coordinator messages: {}", messages.len());

    Ok(())
}
