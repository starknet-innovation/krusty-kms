//! Regression test: a hostile RPC endpoint must not dictate the fee parameters
//! that get signed.
//!
//! A canned-response JSON-RPC server quotes an absurd `l2_gas_price`; the
//! submit paths must refuse before signing. Covers the inflated-gas-price
//! vector — the tip vector is covered by the `FeeBounds::resolve` unit tests.

use krusty_kms_client::{FeeBounds, Wallet};
use krusty_kms_common::address::Address;
use krusty_kms_common::chain::ChainId;
use krusty_kms_common::network::NetworkPreset;
use starknet_rust::core::types::Call;
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Url;
use starknet_types_core::felt::Felt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// An l2 gas price high enough that any plausible gas amount blows past the
/// default ceiling: 1e15 FRI per unit of L2 gas, which resolves to a bound in
/// the thousands of STRK.
const HOSTILE_L2_GAS_PRICE: &str = "0x38d7ea4c68000";

/// The hash the endpoint fabricates in every submission response.
const FABRICATED_TX_HASH: &str = "0xdead";

/// Must stay at zero when a refusal is expected.
type SubmitCounter = Arc<AtomicUsize>;

/// Canned responses. Unlisted methods return an error, so an unexpected extra
/// round trip fails the test rather than passing silently.
fn respond(method: &str, id: &serde_json::Value, submits: &SubmitCounter) -> String {
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
        "starknet_getBlockWithTxs" => serde_json::json!({
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
        }),
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
            submits.fetch_add(1, Ordering::SeqCst);
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
async fn read_request(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<String> {
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

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Spawn the fake endpoint; returns its URL.
async fn spawn_hostile_rpc(submits: SubmitCounter) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let submits = submits.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                while let Some(body) = read_request(&mut stream, &mut buf).await {
                    let req: serde_json::Value = match serde_json::from_str(&body) {
                        Ok(v) => v,
                        Err(_) => return,
                    };
                    let method = req["method"].as_str().unwrap_or_default();
                    let payload = respond(method, &req["id"], &submits);
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

fn dummy_call() -> Call {
    Call {
        to: starknet_rust::core::types::Felt::from_hex_unchecked("0x1"),
        selector: starknet_rust::core::types::Felt::from_hex_unchecked("0x2"),
        calldata: vec![],
    }
}

#[tokio::test]
async fn hostile_gas_price_is_refused_before_signing() {
    let submits: SubmitCounter = Arc::new(AtomicUsize::new(0));
    let url = spawn_hostile_rpc(submits.clone()).await;

    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
        Url::parse(&url).expect("url"),
    )));
    let network = NetworkPreset {
        chain_id: ChainId::Sepolia,
        rpc_url: url.clone(),
        explorer_base_url: String::new(),
        name: "hostile".into(),
    };

    let wallet = Wallet::from_private_key_at_address(
        provider,
        Felt::from_hex_unchecked("0x1234"),
        Address::from(Felt::from_hex_unchecked("0xabc")),
        ChainId::Sepolia,
        network,
    );

    let result = wallet.execute(vec![dummy_call()]).await;

    assert_eq!(
        submits.load(Ordering::SeqCst),
        0,
        "a transaction was signed and submitted with endpoint-dictated fees"
    );
    let err = match result {
        Ok(_) => panic!("execute must refuse an over-ceiling fee, but it submitted"),
        Err(e) => e.to_string(),
    };
    // Specific on purpose: `contains("fee")` would also match
    // `FeeEstimationFailed` and pass vacuously if the canned estimate broke.
    assert!(
        err.contains("fee bounds exceeded"),
        "error should name the fee ceiling, got: {err}"
    );
}

#[tokio::test]
async fn hostile_gas_price_is_refused_before_signing_a_deployment() {
    use krusty_kms::{OpenZeppelinAccount, SaltPolicy};
    use starknet_rust::signers::SigningKey;

    let submits: SubmitCounter = Arc::new(AtomicUsize::new(0));
    let url = spawn_hostile_rpc(submits.clone()).await;

    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
        Url::parse(&url).expect("url"),
    )));
    let network = NetworkPreset {
        chain_id: ChainId::Sepolia,
        rpc_url: url.clone(),
        explorer_base_url: String::new(),
        name: "hostile".into(),
    };

    let signing_key = SigningKey::from_secret_scalar(
        starknet_rust::core::types::Felt::from_hex_unchecked("0x1234"),
    );
    let account_class = OpenZeppelinAccount::from_class_hash(Felt::from_hex_unchecked("0xdef"));

    let result = krusty_kms_client::deploy_oz_account(
        provider,
        &signing_key,
        &account_class,
        SaltPolicy::Zero,
        ChainId::Sepolia,
        network,
    )
    .await;

    assert_eq!(
        submits.load(Ordering::SeqCst),
        0,
        "a deployment was signed and submitted with endpoint-dictated fees"
    );
    let err = match result {
        Ok(_) => panic!("deploy must refuse an over-ceiling fee, but it submitted"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("fee bounds exceeded"),
        "error should name the fee ceiling, got: {err}"
    );
}

/// A transaction must be tracked by the hash we signed, not the one the
/// endpoint echoes back.
#[tokio::test]
async fn submitted_transaction_is_tracked_by_the_locally_computed_hash() {
    let submits: SubmitCounter = Arc::new(AtomicUsize::new(0));
    let url = spawn_hostile_rpc(submits.clone()).await;

    let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(
        Url::parse(&url).expect("url"),
    )));
    let network = NetworkPreset {
        chain_id: ChainId::Sepolia,
        rpc_url: url.clone(),
        explorer_base_url: String::new(),
        name: "hostile".into(),
    };

    // Ceiling lifted so we reach submission; this test is about the hash.
    let wallet = Wallet::from_private_key_at_address(
        provider,
        Felt::from_hex_unchecked("0x1234"),
        Address::from(Felt::from_hex_unchecked("0xabc")),
        ChainId::Sepolia,
        network,
    )
    .with_fee_bounds(FeeBounds {
        max_fee_fri: u128::MAX,
        ..FeeBounds::default()
    });

    let tx = wallet
        .execute(vec![dummy_call()])
        .await
        .expect("submission should succeed once the ceiling allows it");

    assert_eq!(submits.load(Ordering::SeqCst), 1, "expected one submission");
    assert_ne!(
        tx.hash(),
        starknet_rust::core::types::Felt::from_hex_unchecked(FABRICATED_TX_HASH),
        "tracked the hash the endpoint made up instead of the one we signed"
    );
}
