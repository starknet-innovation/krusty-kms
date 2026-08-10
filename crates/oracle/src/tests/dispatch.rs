//! Request dispatch and stdio serving behavior.

use super::fixtures::{sample_account_descriptor, sample_derivation_request, FakeHandler};
use crate::StdioOracle;
use krusty_kms_common::ChainId;
use krusty_kms_domain::{
    CachePolicy, FeltHex, GatewayErrorCode, OperationId, OperationLookupResult, OracleCommand,
    OracleOutcome, OracleRequest, OracleResponse, OracleResult, ProtocolVersion, QueryMode,
    RequestId, TrackedToken,
};
use std::sync::Arc;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn handle_request_dispatches_derive_account() {
    let oracle = StdioOracle::new(FakeHandler::new());
    let response = oracle
        .handle_request(OracleRequest {
            version: ProtocolVersion::V1_0,
            id: RequestId::new("req-1").unwrap(),
            confirm: false,
            command: OracleCommand::DeriveAccount(sample_derivation_request()),
        })
        .await;

    match response.outcome {
        OracleOutcome::Ok { result } => match *result {
            OracleResult::DeriveAccount(result) => {
                assert_eq!(result.operation.id.as_str(), "derive-1");
                assert_eq!(
                    result.value.address.as_str(),
                    sample_account_descriptor().address.as_str()
                );
            }
            other => panic!("unexpected response: {:?}", other),
        },
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn handle_request_rejects_unsupported_protocol_version() {
    let oracle = StdioOracle::new(FakeHandler::new());
    let response = oracle
        .handle_request(OracleRequest {
            version: ProtocolVersion { major: 9, minor: 9 },
            id: RequestId::new("req-2").unwrap(),
            confirm: false,
            command: OracleCommand::GetProtocolInfo,
        })
        .await;

    match response.outcome {
        OracleOutcome::Error { error } => {
            assert_eq!(error.code, GatewayErrorCode::UnsupportedProtocolVersion);
            assert!(!error.retryable);
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn handle_line_returns_invalid_request_for_bad_json() {
    let oracle = StdioOracle::new(FakeHandler::new());
    let response = oracle.handle_line("{not valid json").await;

    assert!(response.id.is_none());
    match response.outcome {
        OracleOutcome::Error { error } => {
            assert_eq!(error.code, GatewayErrorCode::InvalidRequest);
        }
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn serve_writes_jsonl_responses() {
    let oracle = Arc::new(StdioOracle::new(FakeHandler::new()));
    let (mut client_in, server_in) = duplex(4096);
    let (server_out, mut client_out) = duplex(4096);

    let server = {
        let oracle = oracle.clone();
        tokio::spawn(async move { oracle.serve(server_in, server_out).await.unwrap() })
    };

    let request = serde_json::to_vec(&OracleRequest {
        version: ProtocolVersion::V1_0,
        id: RequestId::new("req-3").unwrap(),
        confirm: false,
        command: OracleCommand::GetOperationStatus(krusty_kms_domain::GetOperationStatusRequest {
            operation_id: OperationId::new("op-1").unwrap(),
        }),
    })
    .unwrap();
    client_in.write_all(&request).await.unwrap();
    client_in.write_all(b"\n").await.unwrap();
    drop(client_in);

    let mut output = Vec::new();
    client_out.read_to_end(&mut output).await.unwrap();
    server.await.unwrap();

    let line = String::from_utf8(output).unwrap();
    let response: OracleResponse = serde_json::from_str(line.trim()).unwrap();

    match response.outcome {
        OracleOutcome::Ok { result } => match *result {
            OracleResult::GetOperationStatus(result) => match result {
                OperationLookupResult::Found { operation } => {
                    assert_eq!(operation.id.as_str(), "op-1");
                }
                other => panic!("unexpected lookup result: {:?}", other),
            },
            other => panic!("unexpected response: {:?}", other),
        },
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn protocol_info_command_is_available() {
    let oracle = StdioOracle::new(FakeHandler::new());
    let response = oracle
        .handle_request(OracleRequest {
            version: ProtocolVersion::V1_0,
            id: RequestId::new("req-4").unwrap(),
            confirm: false,
            command: OracleCommand::GetProtocolInfo,
        })
        .await;

    match response.outcome {
        OracleOutcome::Ok { result } => match *result {
            OracleResult::ProtocolInfo(info) => {
                assert_eq!(info.version, ProtocolVersion::V1_0);
                assert_eq!(info.transport, "stdio-jsonl");
            }
            other => panic!("unexpected response: {:?}", other),
        },
        other => panic!("unexpected response: {:?}", other),
    }
}

#[tokio::test]
async fn query_snapshot_command_roundtrips_domain_payloads() {
    let oracle = StdioOracle::new(FakeHandler::new());
    let response = oracle
        .handle_request(OracleRequest {
            version: ProtocolVersion::V1_0,
            id: RequestId::new("req-5").unwrap(),
            confirm: false,
            command: OracleCommand::QueryAccountSnapshot(
                krusty_kms_domain::AccountSnapshotRequest {
                    chain_id: ChainId::Sepolia,
                    address: FeltHex::parse("0x999").unwrap(),
                    tokens: vec![TrackedToken {
                        symbol: "STRK".to_string(),
                        address: FeltHex::parse("0x456").unwrap(),
                        decimals: 18,
                    }],
                    block: krusty_kms_domain::BlockSelector::Latest,
                    mode: QueryMode::ActiveView,
                    cache_policy: CachePolicy::new(1_000, 500, 8).unwrap(),
                },
            ),
        })
        .await;

    match response.outcome {
        OracleOutcome::Ok { result } => match *result {
            OracleResult::QueryAccountSnapshot(result) => {
                assert_eq!(
                    result.value.address.as_str(),
                    "0x0000000000000000000000000000000000000000000000000000000000000999"
                );
                assert_eq!(result.value.balances[0].amount_raw, "42");
            }
            other => panic!("unexpected response: {:?}", other),
        },
        other => panic!("unexpected response: {:?}", other),
    }
}
