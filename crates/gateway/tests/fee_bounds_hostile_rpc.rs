//! Regression test: the gateway's deploy path must refuse endpoint-dictated
//! fees, and must not advertise that refusal as retryable.
//!
//! The flag matters as much as the refusal: `map_kms_error` would classify this
//! as retryable `RpcDegraded`, and a client honouring that would loop forever.

use krusty_kms_common::{ChainId, FeeBounds, NetworkPreset, SecretFelt, ONE_STRK_FRI};
use krusty_kms_domain::{
    AccountDescriptor, DeployMode, DerivationPath, FeltHex, GatewayErrorCode, KeyDomain, Provenance,
};
use krusty_kms_gateway::{GatewayBackend, StarknetGatewayBackend};
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Url;
use starknet_rust::signers::SigningKey;
use starknet_types_core::felt::Felt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// High enough to blow past the default ceiling by orders of magnitude.
const HOSTILE_L2_GAS_PRICE: &str = "0x38d7ea4c68000";

const TEST_PRIVATE_KEY: &str = "0x1234";

#[derive(Default)]
struct RpcState {
    submits: AtomicUsize,
    submitted_tip: Mutex<Option<serde_json::Value>>,
}

type SharedRpcState = Arc<RpcState>;

fn respond(req: &serde_json::Value, state: &RpcState) -> String {
    let method = req["method"].as_str().unwrap_or_default();
    let id = &req["id"];
    let result = match method {
        "starknet_getNonce" => serde_json::json!("0x0"),
        "starknet_specVersion" => serde_json::json!("0.9.0"),
        "starknet_chainId" => serde_json::json!("0x534e5f5345504f4c4941"),
        // Report the account absent so the deploy proceeds to submit.
        "starknet_getClassHashAt" => {
            return error_response(id, 20, "Contract not found");
        }
        "starknet_estimateFee" => serde_json::json!([{
            "l1_gas_consumed": "0x100",
            "l1_gas_price": "0x100",
            "l2_gas_consumed": "0x100000",
            "l2_gas_price": HOSTILE_L2_GAS_PRICE,
            "l1_data_gas_consumed": "0x100",
            "l1_data_gas_price": "0x100",
            "overall_fee": "0x38d7ea4c680000000",
            "unit": "FRI",
        }]),
        "starknet_addDeployAccountTransaction" => {
            state.submits.fetch_add(1, Ordering::SeqCst);
            *state.submitted_tip.lock().expect("submitted_tip lock") = req["params"]
                .get("deploy_account_transaction")
                .and_then(|tx| tx.get("tip"))
                .cloned();
            serde_json::json!({ "transaction_hash": "0xdead", "contract_address": "0xabc" })
        }
        other => return error_response(id, -32601, &format!("unexpected method {other}")),
    };

    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

fn error_response(id: &serde_json::Value, code: i64, message: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
    .to_string()
}

async fn read_request(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<String> {
    loop {
        if let Some(head_end) = find(buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
            let len: usize = head
                .split("content-length:")
                .nth(1)
                .and_then(|rest| rest.split('\r').next())
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            let body_start = head_end + 4;
            if buf.len() >= body_start + len {
                let body = String::from_utf8_lossy(&buf[body_start..body_start + len]).to_string();
                buf.drain(..body_start + len);
                return Some(body);
            }
        }

        let mut chunk = [0u8; 4096];
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

async fn spawn_hostile_rpc(state: SharedRpcState) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let state = state.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                while let Some(body) = read_request(&mut stream, &mut buf).await {
                    let Ok(req) = serde_json::from_str::<serde_json::Value>(&body) else {
                        return;
                    };
                    let payload = respond(&req, &state);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\n\r\n{}",
                        payload.len(),
                        payload
                    );
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    format!("http://127.0.0.1:{}", addr.port())
}

/// Matches `TEST_PRIVATE_KEY` so validation passes and we reach the fee path.
fn descriptor_for(signing_key: &SigningKey) -> AccountDescriptor {
    let public_key = Felt::from_bytes_be(&signing_key.verifying_key().scalar().to_bytes_be());
    AccountDescriptor {
        address: FeltHex::from_felt(Felt::from_hex_unchecked("0xabc")),
        public_key: FeltHex::from_felt(public_key),
        class_hash: FeltHex::from_felt(Felt::from_hex_unchecked("0xdef")),
        salt: FeltHex::from_felt(Felt::ZERO),
        constructor_calldata: vec![FeltHex::from_felt(public_key)],
        deployer_address: FeltHex::from_felt(Felt::ZERO),
        provenance: Provenance {
            chain_id: ChainId::Sepolia,
            key_domain: KeyDomain::StarknetAccount,
            derivation_path: DerivationPath {
                coin_type: 9004,
                account_index: 0,
                address_index: 0,
            },
            class_hash: None,
        },
    }
}

#[tokio::test]
async fn hostile_gas_price_is_refused_and_not_retryable() {
    let state = Arc::new(RpcState::default());
    let url = spawn_hostile_rpc(state.clone()).await;

    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
        Url::parse(&url).expect("url"),
    )));
    let network = NetworkPreset {
        chain_id: ChainId::Sepolia,
        rpc_url: url.clone(),
        explorer_base_url: String::new(),
        name: "hostile".into(),
    };
    let backend = StarknetGatewayBackend::new(provider, network)
        .with_fee_bounds(FeeBounds::default().with_max_fee_fri(ONE_STRK_FRI));

    let signing_key = SigningKey::from_secret_scalar(
        starknet_rust::core::types::Felt::from_hex_unchecked(TEST_PRIVATE_KEY),
    );
    let private_key = SecretFelt::new(Felt::from_hex_unchecked(TEST_PRIVATE_KEY));

    let result = backend
        .deploy_open_zeppelin(
            &private_key,
            &descriptor_for(&signing_key),
            DeployMode::SubmitOnly,
        )
        .await;

    assert_eq!(
        state.submits.load(Ordering::SeqCst),
        0,
        "a deployment was signed and submitted with endpoint-dictated fees"
    );

    let error = result.expect_err("deploy must refuse an over-ceiling fee");
    assert!(
        error
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("fee approval required"),
        "error should request approval for the higher fee, got: {error:?}"
    );
    assert!(
        !error.retryable,
        "a deterministic fee refusal must not be advertised as retryable"
    );
    assert_eq!(
        error.code,
        GatewayErrorCode::InvalidRequest,
        "the caller's own bounds rejected this, not the RPC"
    );
}

#[tokio::test]
async fn approved_deployment_pins_tip_and_tracks_the_local_hash() {
    let state = Arc::new(RpcState::default());
    let url = spawn_hostile_rpc(state.clone()).await;
    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
        Url::parse(&url).expect("url"),
    )));
    let network = NetworkPreset {
        chain_id: ChainId::Sepolia,
        rpc_url: url,
        explorer_base_url: String::new(),
        name: "hostile".into(),
    };
    let backend = StarknetGatewayBackend::new(provider, network)
        .with_fee_bounds(FeeBounds::default().with_max_fee_fri(u128::MAX));
    let signing_key = SigningKey::from_secret_scalar(
        starknet_rust::core::types::Felt::from_hex_unchecked(TEST_PRIVATE_KEY),
    );
    let private_key = SecretFelt::new(Felt::from_hex_unchecked(TEST_PRIVATE_KEY));

    let result = backend
        .deploy_open_zeppelin(
            &private_key,
            &descriptor_for(&signing_key),
            DeployMode::SubmitOnly,
        )
        .await
        .expect("approved deployment should submit");

    assert_eq!(
        state.submits.load(Ordering::SeqCst),
        1,
        "expected one submission"
    );
    assert_eq!(
        state
            .submitted_tip
            .lock()
            .expect("submitted_tip lock")
            .as_ref(),
        Some(&serde_json::json!("0x0")),
        "the signed deployment did not carry the caller's zero tip"
    );
    let tx_hash = match result {
        krusty_kms_gateway::DeployExecution::Submitted { tx_hash } => tx_hash,
        other => panic!("expected submitted deployment, got {other:?}"),
    };
    assert_ne!(
        tx_hash.to_felt(),
        Felt::from_hex_unchecked("0xdead"),
        "tracked the hash the endpoint made up instead of the one we signed"
    );
}
