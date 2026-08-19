//! Regression test: a hostile RPC endpoint must not dictate the fee parameters
//! that get signed.
//!
//! A canned-response JSON-RPC server quotes an absurd `l2_gas_price`; the
//! submit paths must refuse before signing. Successful paths also prove that
//! the signed transaction pins its tip and ignores a fabricated response hash.

use krusty_kms::{OpenZeppelinAccount, SaltPolicy};
use krusty_kms_client::{FeeBounds, Wallet, ONE_STRK_FRI};
use krusty_kms_common::address::Address;
use krusty_kms_common::chain::ChainId;
use krusty_kms_common::network::NetworkPreset;
use starknet_rust::core::types::Call;
use starknet_rust::providers::jsonrpc::{HttpTransport, JsonRpcClient};
use starknet_rust::providers::Url;
use starknet_rust::signers::SigningKey;
use starknet_types_core::felt::Felt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// An l2 gas price high enough that any plausible gas amount blows past the
/// test's one-STRK approval: 1e15 FRI per unit of L2 gas, which resolves to a
/// bound in the thousands of STRK.
const HOSTILE_L2_GAS_PRICE: &str = "0x38d7ea4c68000";

/// The hash the endpoint fabricates in every submission response.
const FABRICATED_TX_HASH: &str = "0xdead";

#[derive(Default)]
struct RpcState {
    submits: AtomicUsize,
    block_requests: AtomicUsize,
    submitted_tip: Mutex<Option<serde_json::Value>>,
}

type SharedRpcState = Arc<RpcState>;

/// Canned responses. Unlisted methods return an error, so an unexpected extra
/// round trip fails the test rather than passing silently.
fn respond(req: &serde_json::Value, state: &RpcState) -> String {
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

async fn hostile_context() -> (
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

fn dummy_call() -> Call {
    Call {
        to: starknet_rust::core::types::Felt::from_hex_unchecked("0x1"),
        selector: starknet_rust::core::types::Felt::from_hex_unchecked("0x2"),
        calldata: vec![],
    }
}

fn assert_tip_was_pinned(state: &RpcState) {
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

fn assert_fee_was_refused<T, E: std::fmt::Display>(state: &RpcState, result: &Result<T, E>) {
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
