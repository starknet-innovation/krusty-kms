use super::*;
use crate::provider_error_message;
use starknet_rust_core::types::BlockId;
use starknet_rust_core::types::BlockTag;
use starknet_rust_providers::{Provider, ProviderError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Serve one HTTP response per connection, `connections` times, ignoring
/// the request. `chunked` streams the body without a `Content-Length`.
async fn serve(body: Vec<u8>, chunked: bool, connections: usize) -> Url {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..connections {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = vec![0u8; 64 * 1024];
            let _ = socket.read(&mut request).await;
            let head = if chunked {
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n".to_string()
            } else {
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                )
            };
            let _ = socket.write_all(head.as_bytes()).await;
            if chunked {
                for piece in body.chunks(1024) {
                    let frame = format!("{:x}\r\n", piece.len());
                    let _ = socket.write_all(frame.as_bytes()).await;
                    let _ = socket.write_all(piece).await;
                    let _ = socket.write_all(b"\r\n").await;
                }
                let _ = socket.write_all(b"0\r\n\r\n").await;
            } else {
                let _ = socket.write_all(&body).await;
            }
            let _ = socket.shutdown().await;
        }
    });
    Url::parse(&format!("http://{address}/rpc")).unwrap()
}

fn block_number_body() -> Vec<u8> {
    br#"{"jsonrpc":"2.0","id":1,"result":42}"#.to_vec()
}

/// A valid JSON-RPC reply padded with whitespace to `size` bytes.
fn padded_body(size: usize) -> Vec<u8> {
    let mut body = block_number_body();
    body.resize(size, b' ');
    body
}

fn client(url: Url, limit: usize) -> StarknetRpcClient {
    JsonRpcClient::new(BoundedHttpTransport::new(url).with_max_response_bytes(limit))
}

fn assert_too_large(error: &ProviderError, limit: usize) {
    let ProviderError::Other(inner) = error else {
        panic!("expected a transport error, got {error:?}");
    };
    let inner = inner
        .as_any()
        .downcast_ref::<starknet_rust_providers::jsonrpc::JsonRpcClientError<BoundedHttpTransportError>>()
        .expect("BoundedHttpTransport error");
    assert!(
        matches!(
            inner,
            starknet_rust_providers::jsonrpc::JsonRpcClientError::TransportError(
                BoundedHttpTransportError::ResponseTooLarge { limit: l }
            ) if *l == limit
        ),
        "{inner:?}"
    );
}

#[test]
fn default_cap_is_16_mib() {
    let transport = BoundedHttpTransport::new(Url::parse("http://127.0.0.1:1").unwrap());
    assert_eq!(transport.max_response_bytes(), 16 * 1024 * 1024);
    assert_eq!(
        transport.max_response_bytes(),
        DEFAULT_MAX_RPC_RESPONSE_BYTES
    );
}

#[test]
fn append_capped_accepts_exactly_the_limit() {
    let mut body = Vec::new();
    append_capped(&mut body, &[1; 6], 10).unwrap();
    append_capped(&mut body, &[2; 4], 10).unwrap();
    assert_eq!(body.len(), 10);
    assert!(append_capped(&mut body, &[3], 10).is_err());
    assert_eq!(body.len(), 10, "a refused chunk is not appended");
}

#[tokio::test]
async fn body_within_cap_is_parsed() {
    let body = padded_body(4096);
    let url = serve(body, false, 1).await;
    assert_eq!(client(url, 4096).block_number().await.unwrap(), 42);
}

#[tokio::test]
async fn declared_length_over_cap_is_refused() {
    let url = serve(padded_body(4097), false, 1).await;
    let error = client(url, 4096).block_number().await.unwrap_err();
    assert_too_large(&error, 4096);
}

#[tokio::test]
async fn streamed_body_over_cap_is_refused_without_content_length() {
    let url = serve(padded_body(64 * 1024), true, 1).await;
    let error = client(url, 4096).block_number().await.unwrap_err();
    assert_too_large(&error, 4096);
}

#[tokio::test]
async fn streamed_body_within_cap_is_parsed() {
    let url = serve(padded_body(8 * 1024), true, 1).await;
    assert_eq!(client(url, 8 * 1024).block_number().await.unwrap(), 42);
}

#[tokio::test]
async fn oversized_response_message_names_the_limit_not_the_endpoint() {
    let listener_url = serve(padded_body(4097), false, 1).await;
    let mut url = listener_url;
    url.set_query(Some("apikey=SECRET_TOKEN"));
    let error = client(url, 4096).block_number().await.unwrap_err();
    let message = provider_error_message(&error);
    assert_eq!(
        message,
        "provider transport error: response exceeds 4096 bytes"
    );
    assert!(!message.contains("SECRET_TOKEN"));
}

#[tokio::test]
async fn batch_responses_are_reordered_by_id() {
    let body =
        br#"[{"jsonrpc":"2.0","id":1,"result":"0x2"},{"jsonrpc":"2.0","id":0,"result":"0x1"}]"#
            .to_vec();
    let url = serve(body, false, 1).await;
    let transport = BoundedHttpTransport::new(url);
    let requests = [
        ProviderRequestData::GetNonce(starknet_rust_core::types::requests::GetNonceRequest {
            block_id: BlockId::Tag(BlockTag::Latest),
            contract_address: starknet_rust_core::types::Felt::ONE,
        }),
        ProviderRequestData::GetNonce(starknet_rust_core::types::requests::GetNonceRequest {
            block_id: BlockId::Tag(BlockTag::Latest),
            contract_address: starknet_rust_core::types::Felt::TWO,
        }),
    ];
    let responses = transport.send_requests(requests).await.unwrap();
    let results: Vec<_> = responses
        .into_iter()
        .map(|response| match response {
            JsonRpcResponse::Success { result, .. } => result,
            JsonRpcResponse::Error { error, .. } => panic!("{error:?}"),
        })
        .collect();
    assert_eq!(
        results,
        vec![serde_json::json!("0x1"), serde_json::json!("0x2")]
    );
}

#[test]
fn batch_with_unknown_or_null_id_is_refused() {
    let unknown = parse_batch(br#"[{"jsonrpc":"2.0","id":5,"result":1}]"#).unwrap();
    assert!(matches!(
        order_batch(unknown, 2),
        Err(BoundedHttpTransportError::UnexpectedResponseId(5))
    ));
    let null = parse_batch(br#"[{"jsonrpc":"2.0","id":null,"result":1}]"#).unwrap();
    assert!(matches!(
        order_batch(null, 2),
        Err(BoundedHttpTransportError::InvalidNumericResponseId)
    ));
}

#[test]
fn whole_batch_rejection_surfaces_the_rpc_error() {
    let error =
        parse_batch(br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"bad"}}"#)
            .unwrap_err();
    assert!(
        matches!(error, BoundedHttpTransportError::BatchError(ref rpc) if rpc.code == -32600),
        "{error:?}"
    );
}
