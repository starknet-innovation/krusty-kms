//! Devnet integration test for the OpenZeppelin multisig client.
//!
//! Run with:
//!
//! ```bash
//! cargo test -p krusty-kms-client --test oz_multisig_devnet -- --ignored --nocapture
//! ```

use krusty_kms::OpenZeppelinMultisig;
use krusty_kms::SaltPolicy;
use krusty_kms_client::{
    hash_transaction_batch, InMemoryMultisigCoordinator, Multisig, MultisigCall,
    MultisigCoordinationMessage, MultisigCoordinator, MultisigExecutionNotice,
    MultisigSignerNotice, MultisigTransactionState, SignedMultisigCoordinationMessage, WaitOptions,
    Wallet,
};
use krusty_kms_common::{Address, ChainId, NetworkPreset};
use serde_json::Value;
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_types_core::felt::Felt;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

const ALICE_ADDRESS: &str = "0x034ba56f92265f0868c57d3fe72ecab144fc96f97954bbbc4252cef8e8a979ba";
const ALICE_PRIVATE_KEY: &str =
    "0x00000000000000000000000000000000b137668388dbe9acdfa3bc734cc2c469";
const BOB_ADDRESS: &str = "0x02939f2dc3f80cc7d620e8a86f2e69c1e187b7ff44b74056647368b5c49dc370";
const BOB_PRIVATE_KEY: &str = "0x00000000000000000000000000000000e8c2801d899646311100a661d32587aa";
const CHARLIE_ADDRESS: &str = "0x025a6c9f0c15ef30c139065096b4b8e563e6b86191fd600a4f0616df8f22fb77";
const CHARLIE_PRIVATE_KEY: &str =
    "0x000000000000000000000000000000007b2e5d0e627be6ce12ddc6fd0f5ff2fb";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "starts starknet-devnet and declares/deploys Cairo contracts"]
async fn openzeppelin_multisig_flow_on_devnet() {
    let port = free_port();
    let rpc_url = format!("http://127.0.0.1:{port}");
    let _devnet = DevnetProcess::start(port);
    wait_for_devnet(&rpc_url).await;

    let accounts_file = unique_temp_file("krusty-sncast-accounts", "json");
    import_sncast_account(
        &accounts_file,
        &rpc_url,
        "alice",
        ALICE_ADDRESS,
        ALICE_PRIVATE_KEY,
    );

    let contracts_dir = workspace_root().join("contracts/oz_multisig");
    let class_hash = declare_multisig(&contracts_dir, &accounts_file, &rpc_url);

    let alice = Address::from_hex(ALICE_ADDRESS).unwrap();
    let bob = Address::from_hex(BOB_ADDRESS).unwrap();
    let charlie = Address::from_hex(CHARLIE_ADDRESS).unwrap();
    let signers = vec![alice.as_felt(), bob.as_felt(), charlie.as_felt()];
    let descriptor = OpenZeppelinMultisig::from_class_hash(class_hash)
        .deployment_descriptor(2, &signers, SaltPolicy::Explicit(Felt::from(0x1234u64)))
        .unwrap();

    let multisig_address = deploy_multisig(
        &contracts_dir,
        &accounts_file,
        &rpc_url,
        class_hash,
        &descriptor.constructor_calldata,
        descriptor.salt,
    );

    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
        Url::parse(&rpc_url).unwrap(),
    )));
    let network = NetworkPreset {
        chain_id: ChainId::Sepolia,
        rpc_url,
        explorer_base_url: "http://127.0.0.1".to_string(),
        name: "Devnet".to_string(),
    };

    let alice_wallet = devnet_wallet(provider.clone(), ALICE_PRIVATE_KEY, alice, network.clone());
    let bob_wallet = devnet_wallet(provider.clone(), BOB_PRIVATE_KEY, bob, network.clone());
    let charlie_wallet = devnet_wallet(
        provider.clone(),
        CHARLIE_PRIVATE_KEY,
        charlie,
        network.clone(),
    );

    let multisig = Multisig::new(provider, multisig_address, network.chain_id);
    assert_eq!(multisig.get_quorum().await.unwrap(), 2);
    assert!(multisig.is_signer(&alice).await.unwrap());
    assert!(multisig.is_signer(&bob).await.unwrap());
    assert!(multisig.is_signer(&charlie).await.unwrap());

    let target_call = MultisigCall::from_starknet_call(&multisig.populate_change_quorum(3));
    let salt = Felt::from(0x55u64);
    let proposal = multisig.proposal(
        vec![target_call],
        salt,
        alice,
        Some("devnet: raise quorum to 3".to_string()),
    );
    proposal.validate_transaction_id().unwrap();

    let onchain_id = multisig
        .hash_transaction_batch_onchain(&proposal.calls, proposal.salt)
        .await
        .unwrap();
    assert_eq!(
        onchain_id,
        hash_transaction_batch(&proposal.calls, proposal.salt)
    );
    assert_eq!(onchain_id, proposal.transaction_id);

    let coordinator = InMemoryMultisigCoordinator::new();
    let signed_proposal = SignedMultisigCoordinationMessage::sign_with_stark_key(
        MultisigCoordinationMessage::Proposal(proposal.clone()),
        &signing_key(ALICE_PRIVATE_KEY),
    )
    .unwrap();
    // The claimed proposer authenticates against the on-chain signer set and
    // alice's account contract (SNIP-6 `is_valid_signature`).
    assert_eq!(
        multisig
            .verify_signed_message(&signed_proposal)
            .await
            .unwrap(),
        alice
    );
    coordinator
        .publish(signed_proposal.clone().into())
        .await
        .unwrap();

    // A coordinator swapping the claimed proposer must fail verification:
    // bob did not sign this proposal.
    let mut forged_attribution = proposal.clone();
    forged_attribution.proposer = bob;
    let forged_proposal = SignedMultisigCoordinationMessage {
        message: MultisigCoordinationMessage::Proposal(forged_attribution),
        ..signed_proposal
    };
    assert!(multisig
        .verify_signed_message(&forged_proposal)
        .await
        .is_err());

    multisig
        .submit_batch(&alice_wallet, &proposal.calls, proposal.salt)
        .await
        .unwrap()
        .wait(wait_options())
        .await
        .unwrap();
    assert_eq!(
        multisig
            .get_transaction_state(proposal.transaction_id)
            .await
            .unwrap(),
        MultisigTransactionState::Pending
    );

    multisig
        .confirm_proposal(&bob_wallet, &proposal)
        .await
        .unwrap()
        .wait(wait_options())
        .await
        .unwrap();
    let bob_confirmation = SignedMultisigCoordinationMessage::sign_with_stark_key(
        MultisigCoordinationMessage::Confirmation(MultisigSignerNotice::new(
            multisig_address,
            network.chain_id,
            proposal.transaction_id,
            bob,
        )),
        &signing_key(BOB_PRIVATE_KEY),
    )
    .unwrap();
    assert_eq!(
        multisig
            .verify_signed_message(&bob_confirmation)
            .await
            .unwrap(),
        bob
    );
    coordinator
        .publish(bob_confirmation.clone().into())
        .await
        .unwrap();

    // A confirmation forged for bob but signed with charlie's key is rejected
    // by bob's account contract.
    let forged_confirmation = SignedMultisigCoordinationMessage::sign_with_stark_key(
        bob_confirmation.message.clone(),
        &signing_key(CHARLIE_PRIVATE_KEY),
    )
    .unwrap();
    assert!(multisig
        .verify_signed_message(&forged_confirmation)
        .await
        .is_err());

    assert_eq!(
        multisig
            .get_transaction_state(proposal.transaction_id)
            .await
            .unwrap(),
        MultisigTransactionState::Pending
    );

    multisig
        .confirm_proposal(&charlie_wallet, &proposal)
        .await
        .unwrap()
        .wait(wait_options())
        .await
        .unwrap();
    let charlie_confirmation = SignedMultisigCoordinationMessage::sign_with_stark_key(
        MultisigCoordinationMessage::Confirmation(MultisigSignerNotice::new(
            multisig_address,
            network.chain_id,
            proposal.transaction_id,
            charlie,
        )),
        &signing_key(CHARLIE_PRIVATE_KEY),
    )
    .unwrap();
    assert_eq!(
        multisig
            .verify_signed_message(&charlie_confirmation)
            .await
            .unwrap(),
        charlie
    );
    coordinator
        .publish(charlie_confirmation.into())
        .await
        .unwrap();
    assert_eq!(
        multisig
            .get_transaction_state(proposal.transaction_id)
            .await
            .unwrap(),
        MultisigTransactionState::Confirmed
    );

    multisig
        .execute_batch(&charlie_wallet, &proposal.calls, proposal.salt)
        .await
        .unwrap()
        .wait(wait_options())
        .await
        .unwrap();
    let charlie_execution = SignedMultisigCoordinationMessage::sign_with_stark_key(
        MultisigCoordinationMessage::Execution(MultisigExecutionNotice::new(
            multisig_address,
            network.chain_id,
            proposal.transaction_id,
            charlie,
        )),
        &signing_key(CHARLIE_PRIVATE_KEY),
    )
    .unwrap();
    assert_eq!(
        multisig
            .verify_signed_message(&charlie_execution)
            .await
            .unwrap(),
        charlie
    );
    coordinator.publish(charlie_execution.into()).await.unwrap();

    assert_eq!(multisig.get_quorum().await.unwrap(), 3);
    assert_eq!(
        multisig
            .get_transaction_state(proposal.transaction_id)
            .await
            .unwrap(),
        MultisigTransactionState::Executed
    );
    assert_eq!(
        coordinator.messages(&proposal.topic()).await.unwrap().len(),
        4
    );
}

fn wait_options() -> Option<WaitOptions> {
    Some(WaitOptions {
        interval_secs: 1,
        timeout_secs: 30,
    })
}

fn signing_key(private_key: &str) -> starknet_rust::signers::SigningKey {
    starknet_rust::signers::SigningKey::from_secret_scalar(
        starknet_rust::core::types::Felt::from_hex(private_key).unwrap(),
    )
}

fn devnet_wallet(
    provider: Arc<JsonRpcClient<HttpTransport>>,
    private_key: &str,
    address: Address,
    network: NetworkPreset,
) -> Wallet {
    Wallet::from_private_key_at_address(
        provider,
        Felt::from_hex(private_key).unwrap(),
        address,
        ChainId::Sepolia,
        network,
    )
}

fn declare_multisig(contracts_dir: &Path, accounts_file: &Path, rpc_url: &str) -> Felt {
    let output = run(
        "sncast",
        &[
            "--account",
            "alice",
            "--accounts-file",
            accounts_file.to_str().unwrap(),
            "--wait",
            "--json",
            "declare",
            "--contract-name",
            "MultisigWallet",
            "--package",
            "oz_multisig",
            "--url",
            rpc_url,
        ],
        contracts_dir,
    );
    Felt::from_hex(&json_field(&output, "class_hash")).unwrap()
}

fn deploy_multisig(
    contracts_dir: &Path,
    accounts_file: &Path,
    rpc_url: &str,
    class_hash: Felt,
    constructor_calldata: &[Felt],
    salt: Felt,
) -> Address {
    let mut args = vec![
        "--account".to_string(),
        "alice".to_string(),
        "--accounts-file".to_string(),
        accounts_file.to_string_lossy().to_string(),
        "--wait".to_string(),
        "--json".to_string(),
        "deploy".to_string(),
        "--class-hash".to_string(),
        format!("{class_hash:#x}"),
        "--salt".to_string(),
        format!("{salt:#x}"),
        "--constructor-calldata".to_string(),
    ];
    args.extend(constructor_calldata.iter().map(|felt| format!("{felt:#x}")));
    args.push("--url".to_string());
    args.push(rpc_url.to_string());

    let borrowed = args.iter().map(String::as_str).collect::<Vec<_>>();
    let output = run("sncast", &borrowed, contracts_dir);
    Address::from_hex(&json_field(&output, "contract_address")).unwrap()
}

fn import_sncast_account(
    accounts_file: &Path,
    rpc_url: &str,
    name: &str,
    address: &str,
    private_key: &str,
) {
    run(
        "sncast",
        &[
            "--accounts-file",
            accounts_file.to_str().unwrap(),
            "account",
            "import",
            "--name",
            name,
            "--address",
            address,
            "--type",
            "oz",
            "--private-key",
            private_key,
            "--url",
            rpc_url,
            "--silent",
        ],
        &workspace_root(),
    );
}

fn run(program: &str, args: &[&str], current_dir: &Path) -> String {
    let output = Command::new(program)
        .args(args)
        .current_dir(current_dir)
        .output()
        .unwrap_or_else(|error| panic!("failed to run {program}: {error}"));

    if !output.status.success() {
        panic!(
            "{program} failed with status {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    String::from_utf8(output.stdout).unwrap()
}

fn json_field(output: &str, field: &str) -> String {
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find_map(|value| {
            value
                .get(field)
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| panic!("missing JSON field `{field}` in output:\n{output}"))
}

async fn wait_for_devnet(rpc_url: &str) {
    let url = format!("{rpc_url}/is_alive");
    for _ in 0..100 {
        if let Ok(response) = reqwest::get(&url).await {
            if response.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("devnet did not become ready at {url}");
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn unique_temp_file(prefix: &str, extension: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nanos}.{extension}"))
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

struct DevnetProcess {
    child: Child,
}

impl DevnetProcess {
    fn start(port: u16) -> Self {
        let child = Command::new("starknet-devnet")
            .args([
                "--port",
                &port.to_string(),
                "--seed",
                "42",
                "--accounts",
                "3",
                "--initial-balance",
                "1000000000000000000000",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|error| panic!("failed to start starknet-devnet: {error}"));
        Self { child }
    }
}

impl Drop for DevnetProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
