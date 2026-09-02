//! Wallet utility functions for Felt conversion and deployment checking.

use krusty_kms_common::{is_already_deployed_validation_failure, KmsError, Result};
use starknet_rust::accounts::AccountFactoryError;
use starknet_rust::core::types::StarknetError;
use starknet_rust::core::types::{BlockId, BlockTag};
use starknet_rust::providers::jsonrpc::{
    HttpTransport, HttpTransportError, JsonRpcClient, JsonRpcClientError,
};
use starknet_rust::providers::{Provider, ProviderError, ProviderImplError};
use std::sync::Arc;

/// Type alias for starknet-rs Felt.
pub type StarknetRsFelt = starknet_rust::core::types::Felt;
/// Type alias for starknet-types-core Felt.
pub type CoreFelt = starknet_types_core::felt::Felt;

#[async_trait::async_trait]
trait DeploymentProvider: Send + Sync {
    async fn get_class_hash_at(
        &self,
        address: StarknetRsFelt,
    ) -> std::result::Result<StarknetRsFelt, ProviderError>;
}

#[async_trait::async_trait]
impl DeploymentProvider for JsonRpcClient<HttpTransport> {
    async fn get_class_hash_at(
        &self,
        address: StarknetRsFelt,
    ) -> std::result::Result<StarknetRsFelt, ProviderError> {
        Provider::get_class_hash_at(self, BlockId::Tag(BlockTag::Latest), address).await
    }
}

/// Convert from starknet-types-core Felt to starknet-rs Felt.
#[inline]
pub fn core_felt_to_rs(felt: CoreFelt) -> StarknetRsFelt {
    StarknetRsFelt::from_bytes_be(&felt.to_bytes_be())
}

/// Convert from starknet-rs Felt to starknet-types-core Felt.
#[inline]
pub fn rs_felt_to_core(felt: StarknetRsFelt) -> CoreFelt {
    CoreFelt::from_bytes_be(&felt.to_bytes_be())
}

/// Check whether a contract is deployed at the given address.
///
/// Queries `getClassHashAt` — if the call succeeds, the address is deployed.
pub async fn check_deployed(
    provider: &Arc<JsonRpcClient<HttpTransport>>,
    address: StarknetRsFelt,
) -> Result<bool> {
    check_deployed_with_provider(provider.as_ref(), address).await
}

async fn check_deployed_with_provider<P: DeploymentProvider>(
    provider: &P,
    address: StarknetRsFelt,
) -> Result<bool> {
    match provider.get_class_hash_at(address).await {
        Ok(_) => Ok(true),
        Err(error) if is_contract_not_found(&error) => Ok(false),
        Err(error) => Err(rpc_error(error)),
    }
}

/// Map a provider failure to [`KmsError::RpcError`] without the endpoint URL
/// (see [`provider_error_message`]).
pub(crate) fn rpc_error(error: ProviderError) -> KmsError {
    KmsError::RpcError(provider_error_message(&error))
}

/// Describe a provider failure without the endpoint URL.
///
/// Typed JSON-RPC failures keep their upstream message. Transport failures
/// are reduced to a fixed kind: `reqwest::Error`'s `Display` embeds the full
/// request URL, whose path or query usually carries the provider API key.
pub(crate) fn provider_error_message(error: &ProviderError) -> String {
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
        .downcast_ref::<JsonRpcClientError<HttpTransportError>>()
    else {
        return "other".to_string();
    };
    match error {
        JsonRpcClientError::JsonError(_)
        | JsonRpcClientError::TransportError(HttpTransportError::Json(_)) => "decode".to_string(),
        JsonRpcClientError::JsonRpcError(rpc) => format!("json-rpc code {}", rpc.code),
        JsonRpcClientError::TransportError(HttpTransportError::Reqwest(http)) => {
            http_error_kind(http)
        }
        JsonRpcClientError::TransportError(HttpTransportError::UnexpectedResponseId(_)) => {
            "other".to_string()
        }
    }
}

fn http_error_kind(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "timeout".to_string()
    } else if error.is_connect() {
        "connect".to_string()
    } else if let Some(status) = error.status() {
        format!("status {}", status.as_u16())
    } else if error.is_decode() {
        "decode".to_string()
    } else {
        "other".to_string()
    }
}

pub(crate) fn map_deploy_factory_error<S: std::fmt::Display>(
    error: AccountFactoryError<S>,
) -> KmsError {
    match error {
        AccountFactoryError::Provider(error) => map_deploy_provider_error(error),
        AccountFactoryError::Signing(error) => KmsError::CryptoError(error.to_string()),
        AccountFactoryError::FeeOutOfRange => {
            KmsError::TransactionError("fee calculation overflow".to_string())
        }
    }
}

fn map_deploy_provider_error(error: ProviderError) -> KmsError {
    match error {
        ProviderError::StarknetError(error) => map_deploy_starknet_error(error),
        other => rpc_error(other),
    }
}

fn map_deploy_starknet_error(error: StarknetError) -> KmsError {
    match error {
        StarknetError::ClassHashNotFound => KmsError::InvalidClassHash(error.to_string()),
        StarknetError::ContractNotFound => KmsError::ContractNotFound(error.to_string()),
        StarknetError::InsufficientAccountBalance
        | StarknetError::InsufficientResourcesForValidate => {
            KmsError::InsufficientFeeBalance(error.to_string())
        }
        StarknetError::ValidationFailure(message) => {
            if is_already_deployed_validation_failure(&message) {
                KmsError::AlreadyDeployed(message)
            } else {
                KmsError::TransactionError(message)
            }
        }
        StarknetError::UnexpectedError(message) => KmsError::RpcError(message),
        other => KmsError::TransactionError(other.to_string()),
    }
}

fn is_contract_not_found(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::StarknetError(StarknetError::ContractNotFound)
    )
}

#[allow(dead_code)]
pub(crate) fn is_entrypoint_not_found(error: &ProviderError) -> bool {
    matches!(
        error,
        ProviderError::StarknetError(StarknetError::EntrypointNotFound)
    )
}

/// Extract a `u16` from the low 2 bytes of a starknet-rs Felt.
pub(crate) fn felt_to_u16(felt: &StarknetRsFelt) -> u16 {
    let bytes = felt.to_bytes_be();
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&bytes[30..32]);
    u16::from_be_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct MockDeploymentProvider {
        responses: Mutex<VecDeque<std::result::Result<StarknetRsFelt, ProviderError>>>,
        requests: Mutex<Vec<StarknetRsFelt>>,
    }

    impl MockDeploymentProvider {
        fn with_response(response: std::result::Result<StarknetRsFelt, ProviderError>) -> Self {
            Self {
                responses: Mutex::new(VecDeque::from([response])),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl DeploymentProvider for MockDeploymentProvider {
        async fn get_class_hash_at(
            &self,
            address: StarknetRsFelt,
        ) -> std::result::Result<StarknetRsFelt, ProviderError> {
            self.requests.lock().unwrap().push(address);
            self.responses.lock().unwrap().pop_front().unwrap()
        }
    }

    #[tokio::test]
    async fn mocked_provider_classifies_deployment_results() {
        let deployed = MockDeploymentProvider::with_response(Ok(StarknetRsFelt::from(7u64)));
        assert!(
            check_deployed_with_provider(&deployed, StarknetRsFelt::from(9u64))
                .await
                .unwrap()
        );
        assert_eq!(
            deployed.requests.lock().unwrap().as_slice(),
            &[StarknetRsFelt::from(9u64)]
        );

        let missing = MockDeploymentProvider::with_response(Err(ProviderError::StarknetError(
            StarknetError::ContractNotFound,
        )));
        assert!(
            !check_deployed_with_provider(&missing, StarknetRsFelt::from(9u64))
                .await
                .unwrap()
        );
    }

    #[test]
    fn test_felt_roundtrip() {
        let core = CoreFelt::from(0xDEADBEEFu64);
        let rs = core_felt_to_rs(core);
        let back = rs_felt_to_core(rs);
        assert_eq!(core, back);
    }

    #[test]
    fn test_felt_zero() {
        let core = CoreFelt::ZERO;
        let rs = core_felt_to_rs(core);
        assert_eq!(rs, StarknetRsFelt::ZERO);
    }

    #[test]
    fn test_contract_not_found_provider_error_is_treated_as_undeployed() {
        assert!(is_contract_not_found(&ProviderError::StarknetError(
            StarknetError::ContractNotFound,
        )));
        assert!(!is_contract_not_found(&ProviderError::RateLimited));
    }

    #[test]
    fn test_entrypoint_not_found_provider_error_is_treated_as_selector_mismatch() {
        assert!(is_entrypoint_not_found(&ProviderError::StarknetError(
            StarknetError::EntrypointNotFound,
        )));
        assert!(!is_entrypoint_not_found(&ProviderError::RateLimited));
    }

    #[test]
    fn test_deploy_error_maps_typed_class_hash_failure() {
        let error = map_deploy_factory_error(AccountFactoryError::<&str>::Provider(
            ProviderError::StarknetError(StarknetError::ClassHashNotFound),
        ));
        assert!(matches!(error, KmsError::InvalidClassHash(_)));
    }

    #[test]
    fn test_deploy_error_maps_typed_fee_failure() {
        let error = map_deploy_factory_error(AccountFactoryError::<&str>::Provider(
            ProviderError::StarknetError(StarknetError::InsufficientAccountBalance),
        ));
        assert!(matches!(error, KmsError::InsufficientFeeBalance(_)));
    }

    #[test]
    fn test_deploy_error_recognizes_already_deployed_validation_failure() {
        let error = map_deploy_factory_error(AccountFactoryError::<&str>::Provider(
            ProviderError::StarknetError(StarknetError::ValidationFailure(
                "Requested ContractAddress has already been deployed".to_string(),
            )),
        ));
        assert!(matches!(error, KmsError::AlreadyDeployed(_)));
    }

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
        let redacted = "provider transport error: other".to_string();
        assert!(matches!(rpc_error(leaky()), KmsError::RpcError(m) if m == redacted));
        let deploy = map_deploy_factory_error(AccountFactoryError::<&str>::Provider(leaky()));
        assert!(matches!(deploy, KmsError::RpcError(m) if m == redacted));

        let rpc = starknet_rust::providers::jsonrpc::JsonRpcError {
            code: -32000,
            message: "invalid api key SECRET_TOKEN".to_string(),
            data: None,
        };
        let rpc: ProviderError = JsonRpcClientError::<HttpTransportError>::JsonRpcError(rpc).into();
        assert_eq!(
            provider_error_message(&rpc),
            "provider transport error: json-rpc code -32000"
        );
        let json = serde_json::from_str::<u8>("not json").unwrap_err();
        let decode: ProviderError =
            JsonRpcClientError::<HttpTransportError>::JsonError(json).into();
        assert_eq!(
            provider_error_message(&decode),
            "provider transport error: decode"
        );
        let typed = ProviderError::StarknetError(StarknetError::ContractNotFound);
        assert_eq!(
            provider_error_message(&typed),
            StarknetError::ContractNotFound.to_string()
        );
    }

    /// A real `reqwest::Error` from a refused loopback connection: the upstream
    /// `Display` names the URL (including the fake key in the path); ours must
    /// reduce it to the `connect` kind.
    #[tokio::test]
    async fn refused_connection_is_reported_as_connect_without_the_url() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let url = format!("http://127.0.0.1:{port}/v0_9/SECRET_TOKEN");
        let provider = crate::provider::create_provider(&url).unwrap();
        let error = provider.chain_id().await.unwrap_err();
        assert!(error.to_string().contains("SECRET_TOKEN"));

        let message = provider_error_message(&error);
        assert_eq!(message, "provider transport error: connect");
        assert!(!message.contains("SECRET_TOKEN"));
        assert!(!message.contains(&port.to_string()));
    }
}
