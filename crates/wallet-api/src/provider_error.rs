//! Endpoint-safe descriptions of provider failures.
//!
//! `starknet-rust-providers` wraps `reqwest::Error` transparently and its
//! `Display` appends `for url (<full url>)`, so formatting a transport failure
//! copies the RPC endpoint, whose path or query usually carries the provider
//! API key, into the error text. Every place that turns a [`ProviderError`]
//! into text goes through [`provider_error_message`] instead. See
//! `docs/design/2026-09-02-provider-error-redaction.md`.

use crate::rpc_transport::BoundedHttpTransportError as TransportError;
use krusty_kms_common::KmsError;
use starknet_rust_providers::jsonrpc::JsonRpcClientError;
use starknet_rust_providers::{ProviderError, ProviderImplError};

/// Map a provider failure to [`KmsError::RpcError`] without the endpoint URL
/// (see [`provider_error_message`]).
#[must_use]
pub fn rpc_error(error: ProviderError) -> KmsError {
    KmsError::RpcError(provider_error_message(&error))
}

/// Describe a provider failure without the endpoint URL.
///
/// Typed JSON-RPC failures keep their upstream message. Transport failures
/// are reduced to `provider transport error: <kind>` with kind in
/// `timeout | connect | status <code> | decode | json-rpc code <n> |
/// response exceeds <limit> bytes | other`,
/// because `reqwest::Error`'s `Display` embeds the full request URL.
#[must_use]
pub fn provider_error_message(error: &ProviderError) -> String {
    match error {
        ProviderError::Other(inner) => format!(
            "provider transport error: {}",
            transport_error_kind(inner.as_ref())
        ),
        typed => typed.to_string(),
    }
}

fn transport_error_kind(error: &dyn ProviderImplError) -> String {
    let Some(error) = error
        .as_any()
        .downcast_ref::<JsonRpcClientError<TransportError>>()
    else {
        return "other".to_string();
    };
    match error {
        JsonRpcClientError::JsonError(_)
        | JsonRpcClientError::TransportError(TransportError::Json(_)) => "decode".to_string(),
        JsonRpcClientError::JsonRpcError(rpc)
        | JsonRpcClientError::TransportError(TransportError::BatchError(rpc)) => {
            format!("json-rpc code {}", rpc.code)
        }
        JsonRpcClientError::TransportError(TransportError::Reqwest(http)) => {
            if http.is_timeout() {
                "timeout".to_string()
            } else if http.is_connect() {
                "connect".to_string()
            } else if let Some(status) = http.status() {
                format!("status {}", status.as_u16())
            } else if http.is_decode() {
                "decode".to_string()
            } else {
                "other".to_string()
            }
        }
        JsonRpcClientError::TransportError(TransportError::ResponseTooLarge { limit }) => {
            format!("response exceeds {limit} bytes")
        }
        JsonRpcClientError::TransportError(TransportError::UnexpectedResponseId(_))
        | JsonRpcClientError::TransportError(TransportError::InvalidNumericResponseId) => {
            "other".to_string()
        }
    }
}
