use super::{
    classify_transaction_status, effective_wait_bounds, is_transaction_hash_not_found,
    ReceiptObservation, WaitOptions, MAX_WAIT_TIMEOUT_SECS, MIN_WAIT_INTERVAL_SECS,
    MIN_WAIT_TIMEOUT_SECS,
};
use starknet_rust_core::types::{ExecutionResult, StarknetError, TransactionStatus};
use starknet_rust_providers::ProviderError;

#[test]
fn zero_interval_is_raised_to_the_floor() {
    let options = WaitOptions {
        interval_secs: 0,
        timeout_secs: 10,
    };
    assert_eq!(
        effective_wait_bounds(&options),
        (MIN_WAIT_INTERVAL_SECS, 10)
    );
}

#[test]
fn max_timeout_is_capped_and_the_deadline_never_overflows() {
    let options = WaitOptions {
        interval_secs: 5,
        timeout_secs: u64::MAX,
    };
    let (_, timeout_secs) = effective_wait_bounds(&options);
    assert_eq!(timeout_secs, MAX_WAIT_TIMEOUT_SECS);
    // The unbounded value panicked in `Instant + Duration`; the capped one
    // must always fit.
    assert!(tokio::time::Instant::now()
        .checked_add(tokio::time::Duration::from_secs(timeout_secs))
        .is_some());
}

#[test]
fn new_rejects_out_of_range_options() {
    assert!(WaitOptions::new(0, 10).is_err());
    assert!(WaitOptions::new(1, 0).is_err());
    assert!(WaitOptions::new(1, MAX_WAIT_TIMEOUT_SECS + 1).is_err());
    let accepted = WaitOptions::new(MIN_WAIT_INTERVAL_SECS, MAX_WAIT_TIMEOUT_SECS).unwrap();
    assert_eq!(
        (accepted.interval_secs, accepted.timeout_secs),
        (MIN_WAIT_INTERVAL_SECS, MAX_WAIT_TIMEOUT_SECS)
    );
}

#[test]
fn accepted_status_without_receipt_is_not_reported_as_complete_receipt() {
    assert_eq!(
        classify_transaction_status(TransactionStatus::AcceptedOnL2(ExecutionResult::Succeeded,)),
        ReceiptObservation::AcceptedWithoutReceipt
    );
}

#[test]
fn reverted_status_is_terminal() {
    assert_eq!(
        classify_transaction_status(TransactionStatus::PreConfirmed(ExecutionResult::Reverted {
            reason: "constructor failed".to_string(),
        },)),
        ReceiptObservation::Reverted {
            reason: "constructor failed".to_string(),
        }
    );
}

#[test]
fn tx_hash_not_found_is_the_only_pending_lookup_error() {
    assert!(is_transaction_hash_not_found(
        &ProviderError::StarknetError(StarknetError::TransactionHashNotFound,)
    ));
    assert!(!is_transaction_hash_not_found(&ProviderError::RateLimited));
}

/// Codex review: an interval longer than the timeout must not sleep past the
/// deadline, and `new` must reject it up front.
#[test]
fn interval_is_capped_by_the_timeout() {
    let options = WaitOptions {
        interval_secs: 86_400,
        timeout_secs: 1,
    };
    assert_eq!(effective_wait_bounds(&options), (1, 1));
    let huge = WaitOptions {
        interval_secs: u64::MAX,
        timeout_secs: u64::MAX,
    };
    assert_eq!(
        effective_wait_bounds(&huge),
        (MAX_WAIT_TIMEOUT_SECS, MAX_WAIT_TIMEOUT_SECS)
    );
    assert!(WaitOptions::new(2, 1).is_err());
    assert!(WaitOptions::new(1, 1).is_ok());
}

/// Copilot review: field-built options with a zero timeout must resolve to
/// the same lower bound `WaitOptions::new` enforces.
#[test]
fn zero_timeout_is_raised_to_the_floor() {
    let options = WaitOptions {
        interval_secs: 1,
        timeout_secs: 0,
    };
    assert_eq!(
        effective_wait_bounds(&options),
        (MIN_WAIT_INTERVAL_SECS, MIN_WAIT_TIMEOUT_SECS)
    );
    assert!(WaitOptions::new(1, 0).is_err());
    let floor = WaitOptions::new(MIN_WAIT_INTERVAL_SECS, MIN_WAIT_TIMEOUT_SECS).unwrap();
    assert_eq!(
        effective_wait_bounds(&floor),
        (floor.interval_secs, floor.timeout_secs)
    );
}

mod provider_errors {
    use super::super::{provider_error_message, rpc_error, Tx, WaitOptions};
    use crate::{BoundedHttpTransport, BoundedHttpTransportError, StarknetRpcClient};
    use krusty_kms_common::network::NetworkPreset;
    use krusty_kms_common::KmsError;
    use starknet_rust_core::types::{Felt, StarknetError};
    use starknet_rust_providers::jsonrpc::{JsonRpcClient, JsonRpcClientError, JsonRpcError};
    use starknet_rust_providers::{Provider, ProviderError, ProviderImplError};
    use std::sync::Arc;

    /// Stand-in for a transport error whose `Display` leaks the request URL,
    /// the way `reqwest::Error` does.
    #[derive(Debug)]
    struct LeakyTransportError;

    impl std::fmt::Display for LeakyTransportError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("error sending request for url (https://rpc.example.com/v0_9/SECRET_TOKEN)")
        }
    }

    impl std::error::Error for LeakyTransportError {}

    impl ProviderImplError for LeakyTransportError {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    fn transport_errors_are_classified_without_the_endpoint_url() {
        let leaky = || ProviderError::Other(Box::new(LeakyTransportError));
        assert!(leaky().to_string().contains("SECRET_TOKEN"));
        let redacted = "provider transport error: other";
        assert!(matches!(rpc_error(leaky()), KmsError::RpcError(m) if m == redacted));

        let rpc = JsonRpcError {
            code: -32000,
            message: "invalid api key SECRET_TOKEN".to_string(),
            data: None,
        };
        let rpc: ProviderError =
            JsonRpcClientError::<BoundedHttpTransportError>::JsonRpcError(rpc).into();
        assert_eq!(
            provider_error_message(&rpc),
            "provider transport error: json-rpc code -32000"
        );
        let batch = BoundedHttpTransportError::BatchError(JsonRpcError {
            code: -32001,
            message: "SECRET_TOKEN".to_string(),
            data: None,
        });
        let batch: ProviderError =
            JsonRpcClientError::<BoundedHttpTransportError>::TransportError(batch).into();
        assert_eq!(
            provider_error_message(&batch),
            "provider transport error: json-rpc code -32001"
        );
        let invalid: ProviderError =
            JsonRpcClientError::<BoundedHttpTransportError>::TransportError(
                BoundedHttpTransportError::InvalidNumericResponseId,
            )
            .into();
        assert_eq!(
            provider_error_message(&invalid),
            "provider transport error: other"
        );

        let typed = ProviderError::StarknetError(StarknetError::ContractNotFound);
        assert_eq!(
            provider_error_message(&typed),
            StarknetError::ContractNotFound.to_string()
        );
    }

    /// A provider whose every request is refused: the loopback port was
    /// bound and released, and the fake API key sits in the path the way
    /// hosted RPC providers carry it.
    async fn refused_provider() -> (Arc<StarknetRpcClient>, u16) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let url = url::Url::parse(&format!("http://127.0.0.1:{port}/v0_9/SECRET_TOKEN")).unwrap();
        (
            Arc::new(JsonRpcClient::new(BoundedHttpTransport::new(url))),
            port,
        )
    }

    /// Regression for the audit finding: `Tx::wait`, `Tx::receipt` and
    /// `Tx::raw_receipt` used to format the raw `reqwest` error, whose text
    /// names the endpoint URL and so the key.
    #[tokio::test]
    async fn tx_errors_never_contain_the_endpoint_url() {
        let (provider, port) = refused_provider().await;
        let upstream = provider
            .get_transaction_receipt(Felt::ONE)
            .await
            .unwrap_err();
        assert!(upstream.to_string().contains("SECRET_TOKEN"));

        let tx = Tx::new(Felt::ONE, provider, NetworkPreset::devnet());
        let wait = tx
            .wait(Some(WaitOptions::new(1, 1).unwrap()))
            .await
            .unwrap_err();
        let receipt = tx.receipt().await.unwrap_err();
        let raw_receipt = tx.raw_receipt().await.unwrap_err();

        for error in [&wait, &receipt, &raw_receipt] {
            let message = error.to_string();
            assert!(!message.contains("SECRET_TOKEN"), "{message}");
            assert!(!message.contains(&port.to_string()), "{message}");
            assert!(
                message.contains("provider transport error: connect"),
                "{message}"
            );
        }
        assert!(matches!(wait, KmsError::RpcError(_)));
        assert!(matches!(receipt, KmsError::RpcError(_)));
        assert!(matches!(raw_receipt, KmsError::TransactionError(_)));
    }
}
