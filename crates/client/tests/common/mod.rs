#![allow(dead_code)] // each test binary uses a subset

//! Regression test: a hostile RPC endpoint must not dictate the fee parameters
//! that get signed.
//!
//! A canned-response JSON-RPC server quotes an absurd `l2_gas_price`; the
//! submit paths must refuse before signing. Successful paths also prove that
//! the signed transaction pins its tip and ignores a fabricated response hash.

use krusty_kms_common::chain::ChainId;
use krusty_kms_common::network::NetworkPreset;
use starknet_rust::core::types::Call;
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Url;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// An l2 gas price high enough that any plausible gas amount blows past the
/// test's one-STRK approval: 1e15 FRI per unit of L2 gas, which resolves to a
/// bound in the thousands of STRK.
pub const HOSTILE_L2_GAS_PRICE: &str = "0x38d7ea4c68000";

/// The hash the endpoint fabricates in every submission response.
pub const FABRICATED_TX_HASH: &str = "0xdead";

#[derive(Default)]
pub struct RpcState {
    pub submits: AtomicUsize,
    pub block_requests: AtomicUsize,
    pub submitted_tip: Mutex<Option<serde_json::Value>>,
}

pub type SharedRpcState = Arc<RpcState>;

/// Canned responses. Unlisted methods return an error, so an unexpected extra
/// round trip fails the test rather than passing silently.
pub fn respond(req: &serde_json::Value, state: &RpcState) -> String {
    let method = req["method"].as_str().unwrap_or_default();
    let id = &req["id"];
    let result = match method {
        "starknet_getNonce" => serde_json::json!("0x0"),
        "starknet_specVersion" => serde_json::json!("0.9.0"),
        "starknet_chainId" => serde_json::json!("0x534e5f5345504f4c4941"),
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
        // Served so a regression that drops the ceiling still reaches
        // submission, letting the submit counter catch it.
        "starknet_getBlockWithTxs" => {
            state.block_requests.fetch_add(1, Ordering::SeqCst);
            serde_json::json!({
                "status": "ACCEPTED_ON_L2",
                "block_hash": "0x1",
                "parent_hash": "0x0",
                "block_number": 1,
                "new_root": "0x0",
                "timestamp": 0,
                "sequencer_address": "0x0",
                "l1_gas_price": { "price_in_fri": "0x100", "price_in_wei": "0x100" },
                "l2_gas_price": { "price_in_fri": "0x100", "price_in_wei": "0x100" },
                "l1_data_gas_price": { "price_in_fri": "0x100", "price_in_wei": "0x100" },
                "l1_da_mode": "BLOB",
                "starknet_version": "0.14.0",
                "event_commitment": "0x0",
                "transaction_commitment": "0x0",
                "receipt_commitment": "0x0",
                "state_diff_commitment": "0x0",
                "event_count": 0,
                "transaction_count": 0,
                "state_diff_length": 0,
                "transactions": [],
            })
        }
        // Report the account absent so the deploy proceeds to submit.
        "starknet_getClassHashAt" => {
            return serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": 20, "message": "Contract not found" },
            })
            .to_string()
        }
        "starknet_addInvokeTransaction" | "starknet_addDeployAccountTransaction" => {
            state.submits.fetch_add(1, Ordering::SeqCst);
            let transaction = req["params"]
                .get("invoke_transaction")
                .or_else(|| req["params"].get("deploy_account_transaction"));
            *state.submitted_tip.lock().expect("submitted_tip lock") =
                transaction.and_then(|tx| tx.get("tip")).cloned();
            serde_json::json!({ "transaction_hash": FABRICATED_TX_HASH, "contract_address": "0xabc" })
        }
        other => {
            return serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": format!("unexpected method {other}") },
            })
            .to_string()
        }
    };

    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

/// Read one HTTP request off the socket and return its body, or `None` at EOF.
pub async fn read_request(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<String> {
    loop {
        // Headers complete?
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

pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Spawn the fake endpoint; returns its URL.
pub async fn spawn_hostile_rpc(state: SharedRpcState) -> String {
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
                    let req: serde_json::Value = match serde_json::from_str(&body) {
                        Ok(v) => v,
                        Err(_) => return,
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

pub async fn hostile_context() -> (
    SharedRpcState,
    Arc<JsonRpcClient<HttpTransport>>,
    NetworkPreset,
) {
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
    (state, provider, network)
}

pub fn dummy_call() -> Call {
    Call {
        to: starknet_rust::core::types::Felt::from_hex_unchecked("0x1"),
        selector: starknet_rust::core::types::Felt::from_hex_unchecked("0x2"),
        calldata: vec![],
    }
}

pub fn assert_tip_was_pinned(state: &RpcState) {
    assert_eq!(
        state.block_requests.load(Ordering::SeqCst),
        0,
        "the SDK fetched a block median even though the tip was pinned"
    );
    assert_eq!(
        state
            .submitted_tip
            .lock()
            .expect("submitted_tip lock")
            .as_ref(),
        Some(&serde_json::json!("0x0")),
        "the signed transaction did not carry the caller's zero tip"
    );
}

pub fn assert_fee_was_refused<T, E: std::fmt::Display>(state: &RpcState, result: &Result<T, E>) {
    assert_eq!(
        state.submits.load(Ordering::SeqCst),
        0,
        "a transaction was signed and submitted with endpoint-dictated fees"
    );
    let err = match result {
        Ok(_) => panic!("an over-ceiling fee was submitted"),
        Err(error) => error.to_string(),
    };
    assert!(
        err.contains("fee approval required"),
        "error should request approval for the higher fee, got: {err}"
    );
}
