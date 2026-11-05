//! JSON-RPC over HTTP with a byte cap on response bodies.
//!
//! `starknet-rust-providers`' `HttpTransport` reads each response with
//! `reqwest::Response::text()`, which buffers the whole body however large it
//! is, and `reqwest` has no body-size setting. A hostile or compromised RPC
//! endpoint can therefore exhaust memory with one oversized reply within the
//! client's timeouts. [`BoundedHttpTransport`] sends the same JSON-RPC
//! requests but streams each body and stops at
//! [`BoundedHttpTransport::max_response_bytes`]. See
//! `docs/design/2026-11-05-bounded-rpc-transport.md` (audit M-2).

use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};
use starknet_rust_providers::jsonrpc::{
    JsonRpcClient, JsonRpcError, JsonRpcMethod, JsonRpcRequest, JsonRpcResponse, JsonRpcTransport,
};
use starknet_rust_providers::ProviderRequestData;
use url::Url;

/// Default cap on one JSON-RPC response body: 16 MiB.
///
/// The SDK's own calls (contract calls, receipts, event pages, block headers
/// with transaction hashes) are orders of magnitude smaller. Callers that
/// fetch full blocks or contract classes can raise it with
/// [`BoundedHttpTransport::with_max_response_bytes`].
pub const DEFAULT_MAX_RPC_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// The JSON-RPC provider type used across the krusty-kms crates.
pub type StarknetRpcClient = JsonRpcClient<BoundedHttpTransport>;

/// A [`JsonRpcTransport`] over HTTP that refuses response bodies larger than
/// [`max_response_bytes`](Self::max_response_bytes).
///
/// Requests and response parsing match `starknet-rust-providers`'
/// `HttpTransport`; the only difference is the body cap. Request and response
/// bodies are not logged.
#[derive(Debug, Clone)]
pub struct BoundedHttpTransport {
    client: reqwest::Client,
    url: Url,
    headers: Vec<(String, String)>,
    max_response_bytes: usize,
}

/// Errors from [`BoundedHttpTransport`].
#[derive(Debug, thiserror::Error)]
pub enum BoundedHttpTransportError {
    /// HTTP-level failure. Its `Display` includes the endpoint URL; use
    /// [`crate::provider_error_message`] to describe it safely.
    #[error(transparent)]
    Reqwest(reqwest::Error),
    /// JSON serialization or deserialization failure.
    #[error(transparent)]
    Json(serde_json::Error),
    /// The response body exceeded the transport's byte cap.
    #[error("JSON-RPC response body exceeds the {limit} byte limit")]
    ResponseTooLarge {
        /// The cap that was exceeded, in bytes.
        limit: usize,
    },
    /// A batch response carried an id that matches no request.
    #[error("unexpected response ID: {0}")]
    UnexpectedResponseId(u64),
    /// A batch response carried a null or non-numeric id.
    #[error("response has an invalid numeric id")]
    InvalidNumericResponseId,
    /// The server rejected the whole batch with a single JSON-RPC error.
    #[error("batch request rejected: {0}")]
    BatchError(JsonRpcError),
}

type TransportResult<T> = std::result::Result<T, BoundedHttpTransportError>;

#[derive(Serialize)]
struct SingleRequest<P> {
    id: u64,
    jsonrpc: &'static str,
    method: JsonRpcMethod,
    params: P,
}

impl BoundedHttpTransport {
    /// Transport for `url` with a default `reqwest` client and the default cap.
    ///
    /// Production code should prefer `krusty_kms_client::create_provider`,
    /// which also sets timeouts and restricts schemes, proxies and redirects.
    pub fn new(url: impl Into<Url>) -> Self {
        Self::new_with_client(url, reqwest::Client::new())
    }

    /// Transport for `url` using `client`, with the default cap.
    pub fn new_with_client(url: impl Into<Url>, client: reqwest::Client) -> Self {
        Self {
            client,
            url: url.into(),
            headers: Vec::new(),
            max_response_bytes: DEFAULT_MAX_RPC_RESPONSE_BYTES,
        }
    }

    /// Replace the response-body cap. A cap of zero refuses every non-empty
    /// body.
    #[must_use]
    pub fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    /// The response-body cap in bytes.
    #[must_use]
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    /// Append an HTTP header sent with every request.
    #[must_use]
    pub fn with_header(mut self, name: String, value: String) -> Self {
        self.headers.push((name, value));
        self
    }

    /// Append an HTTP header sent with every request.
    pub fn add_header(&mut self, name: String, value: String) {
        self.headers.push((name, value));
    }

    async fn post(&self, body: String) -> TransportResult<Vec<u8>> {
        let mut request = self
            .client
            .post(self.url.clone())
            .body(body)
            .header("Content-Type", "application/json");
        for (name, value) in &self.headers {
            request = request.header(name, value);
        }
        let response = request
            .send()
            .await
            .map_err(BoundedHttpTransportError::Reqwest)?;
        read_capped(response, self.max_response_bytes).await
    }
}

async fn read_capped(mut response: reqwest::Response, limit: usize) -> TransportResult<Vec<u8>> {
    let too_large = || BoundedHttpTransportError::ResponseTooLarge { limit };
    let declared = response.content_length();
    if declared.is_some_and(|length| length > limit as u64) {
        return Err(too_large());
    }
    // `declared` is at most `limit` here, but still only a claim; cap the
    // up-front allocation and let the loop enforce the real bound.
    let capacity = declared.unwrap_or(0).min(64 * 1024) as usize;
    let mut body = Vec::with_capacity(capacity);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(BoundedHttpTransportError::Reqwest)?
    {
        append_capped(&mut body, &chunk, limit).map_err(|()| too_large())?;
    }
    Ok(body)
}

fn append_capped(body: &mut Vec<u8>, chunk: &[u8], limit: usize) -> Result<(), ()> {
    if chunk.len() > limit.saturating_sub(body.len()) {
        return Err(());
    }
    body.extend_from_slice(chunk);
    Ok(())
}

/// Parse a batch body. A server that rejects the whole batch replies with one
/// JSON-RPC error object instead of an array; surface that error.
fn parse_batch(body: &[u8]) -> TransportResult<Vec<JsonRpcResponse<serde_json::Value>>> {
    match serde_json::from_slice(body) {
        Ok(parsed) => Ok(parsed),
        Err(error) => {
            if let Ok(JsonRpcResponse::Error { error, .. }) =
                serde_json::from_slice::<JsonRpcResponse<serde_json::Value>>(body)
            {
                return Err(BoundedHttpTransportError::BatchError(error));
            }
            Err(BoundedHttpTransportError::Json(error))
        }
    }
}

/// Order batch responses by request id; servers need not keep order.
fn order_batch(
    parsed: Vec<JsonRpcResponse<serde_json::Value>>,
    request_count: usize,
) -> TransportResult<Vec<JsonRpcResponse<serde_json::Value>>> {
    let mut responses: Vec<Option<JsonRpcResponse<serde_json::Value>>> = vec![None; request_count];
    for item in parsed {
        let id = match &item {
            JsonRpcResponse::Success { id, .. } | JsonRpcResponse::Error { id, .. } => *id,
        };
        let id = id.ok_or(BoundedHttpTransportError::InvalidNumericResponseId)?;
        let slot = usize::try_from(id)
            .ok()
            .and_then(|index| responses.get_mut(index))
            .ok_or(BoundedHttpTransportError::UnexpectedResponseId(id))?;
        *slot = Some(item);
    }
    Ok(responses.into_iter().flatten().collect())
}

#[async_trait]
impl JsonRpcTransport for BoundedHttpTransport {
    type Error = BoundedHttpTransportError;

    async fn send_request<P, R>(
        &self,
        method: JsonRpcMethod,
        params: P,
    ) -> TransportResult<JsonRpcResponse<R>>
    where
        P: Serialize + Send + Sync,
        R: DeserializeOwned + Send,
    {
        let request = SingleRequest {
            id: 1,
            jsonrpc: "2.0",
            method,
            params,
        };
        let body = serde_json::to_string(&request).map_err(BoundedHttpTransportError::Json)?;
        let response = self.post(body).await?;
        serde_json::from_slice(&response).map_err(BoundedHttpTransportError::Json)
    }

    async fn send_requests<R>(
        &self,
        requests: R,
    ) -> TransportResult<Vec<JsonRpcResponse<serde_json::Value>>>
    where
        R: AsRef<[ProviderRequestData]> + Send + Sync,
    {
        let requests = requests
            .as_ref()
            .iter()
            .enumerate()
            .map(|(index, data)| JsonRpcRequest {
                id: index as u64,
                data: data.clone(),
            })
            .collect::<Vec<_>>();
        let body = serde_json::to_string(&requests).map_err(BoundedHttpTransportError::Json)?;
        let response = self.post(body).await?;
        order_batch(parse_batch(&response)?, requests.len())
    }
}

#[cfg(test)]
mod tests;
