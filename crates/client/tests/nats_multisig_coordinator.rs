//! Live NATS integration test for the multisig coordinator.
//!
//! Run with an installed NATS server:
//!
//! ```bash
//! NATS_SERVER_BIN=/path/to/nats-server \
//!   cargo test -p krusty-kms-client --test nats_multisig_coordinator -- --ignored --nocapture
//! ```
//!
//! If `NATS_SERVER_BIN` and `nats-server` are unavailable, the test tries a
//! Docker `nats:2-alpine` container. If neither path is available, it prints a
//! skip notice and exits successfully.

use futures_util::StreamExt;
use krusty_kms_client::{
    MultisigCall, MultisigCoordinationMessage, MultisigCoordinator, MultisigProposal,
    NatsMultisigCoordinator, SignedMultisigCoordinationMessage,
};
use krusty_kms_common::Address;
use starknet_rust::signers::SigningKey;
use starknet_types_core::felt::Felt;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "starts a local NATS server or Docker container"]
async fn nats_multisig_coordinator_live_pubsub_roundtrip() {
    let port = free_port();
    let Some(_server) = NatsServerProcess::start(port) else {
        eprintln!("skipping live NATS test: no nats-server binary or Docker daemon available");
        return;
    };

    let nats_url = format!("nats://127.0.0.1:{port}");
    let coordinator = wait_for_nats(&nats_url).await;

    let call = MultisigCall::new(
        address(0x999),
        Felt::from(0x123u64),
        vec![Felt::from(42u64)],
    );
    let proposal = MultisigProposal::new(
        address(0x401),
        krusty_kms_common::ChainId::Sepolia,
        vec![call],
        Felt::from(0x55u64),
        address(0x101),
        Some("live NATS integration".to_string()),
    );
    let topic = proposal.topic();
    let proposer_key = SigningKey::from_secret_scalar(0x1234u64.into());
    let signed = SignedMultisigCoordinationMessage::sign_with_stark_key(
        MultisigCoordinationMessage::Proposal(proposal),
        &proposer_key,
    )
    .unwrap();

    let mut subscription = coordinator.subscribe(&topic).await.unwrap();
    coordinator.publish(signed.clone().into()).await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(5), subscription.next())
        .await
        .expect("timed out waiting for NATS coordination message")
        .expect("NATS subscription closed")
        .unwrap();
    assert_eq!(received.as_signed(), Some(&signed));

    // The signature survives the NATS wire roundtrip.
    let public_key = Felt::from_bytes_be(&proposer_key.verifying_key().scalar().to_bytes_be());
    received
        .as_signed()
        .unwrap()
        .verify_with_stark_public_key(public_key)
        .unwrap();

    assert_eq!(
        coordinator.subject(&topic),
        NatsMultisigCoordinator::subject_for("krusty.multisig", &topic)
    );
}

async fn wait_for_nats(url: &str) -> NatsMultisigCoordinator {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        match NatsMultisigCoordinator::connect(url).await {
            Ok(coordinator) => return coordinator,
            Err(error) if tokio::time::Instant::now() < deadline => {
                eprintln!("waiting for NATS at {url}: {error}");
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(error) => panic!("NATS did not become ready at {url}: {error}"),
        }
    }
}

fn address(value: u64) -> Address {
    Address::from(Felt::from(value))
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

enum NatsServerProcess {
    Local { child: Child },
    Docker { name: String, child: Child },
}

impl NatsServerProcess {
    fn start(port: u16) -> Option<Self> {
        if let Some(binary) = nats_server_binary() {
            return Some(Self::start_local(binary, port));
        }

        if docker_available() {
            return Some(Self::start_docker(port));
        }

        None
    }

    fn start_local(binary: PathBuf, port: u16) -> Self {
        let child = Command::new(binary)
            .args(["-p", &port.to_string(), "-js"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|error| panic!("failed to start nats-server: {error}"));
        Self::Local { child }
    }

    fn start_docker(port: u16) -> Self {
        let name = format!("krusty-nats-{}", unique_suffix());
        let port_mapping = format!("127.0.0.1:{port}:4222");
        let child = Command::new("docker")
            .args([
                "run",
                "--rm",
                "--name",
                &name,
                "-p",
                &port_mapping,
                "nats:2-alpine",
                "-js",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|error| panic!("failed to start dockerized NATS: {error}"));
        Self::Docker { name, child }
    }
}

impl Drop for NatsServerProcess {
    fn drop(&mut self) {
        match self {
            Self::Local { child } => {
                let _ = child.kill();
                let _ = child.wait();
            }
            Self::Docker { name, child } => {
                let _ = Command::new("docker").args(["kill", name]).output();
                let _ = child.wait();
            }
        }
    }
}

fn nats_server_binary() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("NATS_SERVER_BIN") {
        return Some(PathBuf::from(path));
    }

    let output = Command::new("which").arg("nats-server").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8(output.stdout).ok()?;
    Some(PathBuf::from(path.trim()))
}

fn docker_available() -> bool {
    Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
