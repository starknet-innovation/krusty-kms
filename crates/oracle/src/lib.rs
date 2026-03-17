//! Versioned stdio oracle transport on top of the gateway surface.
//!
//! Inputs:
//! - newline-delimited JSON requests matching `krusty-kms-domain` oracle types
//! - an `OracleHandler` implementation, typically `krusty-kms-gateway::Gateway`
//!
//! Outputs:
//! - one newline-delimited JSON response per non-empty request line
//! - typed protocol errors for malformed requests, unsupported versions, and gateway failures
//!
//! Invariants:
//! - responses always use the server protocol version
//! - parse failures never panic and return `id: null`
//! - transport does not own secrets, caches, or RPC state; it delegates to the handler

use async_trait::async_trait;
use krusty_kms_domain::{
    AccountDescriptor, AccountSnapshot, CheckDeploymentResult, DeployAccountRequest,
    DeployAccountResult, DerivationRequest, GatewayError, GatewayErrorCode, OperationLookupResult,
    OracleCommand, OracleOutcome, OracleRequest, OracleResponse, OracleResult, ProtocolInfo,
    ProtocolVersion, SignRequest, SignResult, TrackedCommandResult,
};
use krusty_kms_gateway::{Clock, Gateway, GatewayBackend, GatewayResponse, SecretResolver};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// Effectful command surface consumed by the stdio transport.
#[async_trait]
pub trait OracleHandler: Send + Sync {
    /// Transport and version metadata supported by this handler.
    fn protocol_info(&self) -> ProtocolInfo {
        ProtocolInfo::stdio_v1()
    }

    async fn derive_account(
        &self,
        request: DerivationRequest,
    ) -> Result<TrackedCommandResult<AccountDescriptor>, GatewayError>;

    async fn check_deployment(
        &self,
        request: DerivationRequest,
    ) -> Result<TrackedCommandResult<CheckDeploymentResult>, GatewayError>;

    async fn deploy_account(
        &self,
        request: DeployAccountRequest,
    ) -> Result<TrackedCommandResult<DeployAccountResult>, GatewayError>;

    async fn sign(
        &self,
        request: SignRequest,
    ) -> Result<TrackedCommandResult<SignResult>, GatewayError>;

    async fn query_account_snapshot(
        &self,
        request: krusty_kms_domain::AccountSnapshotRequest,
    ) -> Result<TrackedCommandResult<AccountSnapshot>, GatewayError>;

    async fn get_operation_status(
        &self,
        request: krusty_kms_domain::GetOperationStatusRequest,
    ) -> Result<OperationLookupResult, GatewayError>;
}

#[async_trait]
impl<B, S, C> OracleHandler for Gateway<B, S, C>
where
    B: GatewayBackend,
    S: SecretResolver,
    C: Clock + Send + Sync,
{
    async fn derive_account(
        &self,
        request: DerivationRequest,
    ) -> Result<TrackedCommandResult<AccountDescriptor>, GatewayError> {
        self.derive_account(request).await.map(tracked_result)
    }

    async fn check_deployment(
        &self,
        request: DerivationRequest,
    ) -> Result<TrackedCommandResult<CheckDeploymentResult>, GatewayError> {
        self.check_deployment(request).await.map(tracked_result)
    }

    async fn deploy_account(
        &self,
        request: DeployAccountRequest,
    ) -> Result<TrackedCommandResult<DeployAccountResult>, GatewayError> {
        self.deploy_account(request).await.map(tracked_result)
    }

    async fn sign(
        &self,
        request: SignRequest,
    ) -> Result<TrackedCommandResult<SignResult>, GatewayError> {
        self.sign(request).await.map(tracked_result)
    }

    async fn query_account_snapshot(
        &self,
        request: krusty_kms_domain::AccountSnapshotRequest,
    ) -> Result<TrackedCommandResult<AccountSnapshot>, GatewayError> {
        self.query_account_snapshot(request)
            .await
            .map(tracked_result)
    }

    async fn get_operation_status(
        &self,
        request: krusty_kms_domain::GetOperationStatusRequest,
    ) -> Result<OperationLookupResult, GatewayError> {
        Ok(OperationLookupResult {
            operation: self.operation_status(&request.operation_id).await,
        })
    }
}

fn tracked_result<T>(value: GatewayResponse<T>) -> TrackedCommandResult<T> {
    TrackedCommandResult {
        operation: value.operation,
        value: value.value,
    }
}

/// Newline-delimited JSON stdio oracle server.
pub struct StdioOracle<H> {
    handler: H,
}

impl<H> StdioOracle<H>
where
    H: OracleHandler,
{
    pub fn new(handler: H) -> Self {
        Self { handler }
    }

    /// Handle one parsed protocol request.
    pub async fn handle_request(&self, request: OracleRequest) -> OracleResponse {
        let response_id = Some(request.id.clone());
        if request.version != ProtocolVersion::V1_0 {
            return OracleResponse {
                version: ProtocolVersion::V1_0,
                id: response_id,
                outcome: OracleOutcome::Error {
                    error: GatewayError::new(
                        GatewayErrorCode::UnsupportedProtocolVersion,
                        false,
                        Some(format!(
                            "unsupported protocol version {}.{}",
                            request.version.major, request.version.minor
                        )),
                    ),
                },
            };
        }

        let outcome = match request.command {
            OracleCommand::GetProtocolInfo => OracleOutcome::Ok {
                result: Box::new(OracleResult::ProtocolInfo(self.handler.protocol_info())),
            },
            OracleCommand::DeriveAccount(payload) => {
                match self.handler.derive_account(payload).await {
                    Ok(result) => OracleOutcome::Ok {
                        result: Box::new(OracleResult::DeriveAccount(result)),
                    },
                    Err(error) => OracleOutcome::Error { error },
                }
            }
            OracleCommand::CheckDeployment(payload) => {
                match self.handler.check_deployment(payload).await {
                    Ok(result) => OracleOutcome::Ok {
                        result: Box::new(OracleResult::CheckDeployment(result)),
                    },
                    Err(error) => OracleOutcome::Error { error },
                }
            }
            OracleCommand::DeployAccount(payload) => {
                match self.handler.deploy_account(payload).await {
                    Ok(result) => OracleOutcome::Ok {
                        result: Box::new(OracleResult::DeployAccount(result)),
                    },
                    Err(error) => OracleOutcome::Error { error },
                }
            }
            OracleCommand::Sign(payload) => match self.handler.sign(payload).await {
                Ok(result) => OracleOutcome::Ok {
                    result: Box::new(OracleResult::Sign(result)),
                },
                Err(error) => OracleOutcome::Error { error },
            },
            OracleCommand::QueryAccountSnapshot(payload) => {
                match self.handler.query_account_snapshot(payload).await {
                    Ok(result) => OracleOutcome::Ok {
                        result: Box::new(OracleResult::QueryAccountSnapshot(result)),
                    },
                    Err(error) => OracleOutcome::Error { error },
                }
            }
            OracleCommand::GetOperationStatus(payload) => {
                match self.handler.get_operation_status(payload).await {
                    Ok(result) => OracleOutcome::Ok {
                        result: Box::new(OracleResult::GetOperationStatus(result)),
                    },
                    Err(error) => OracleOutcome::Error { error },
                }
            }
        };

        OracleResponse {
            version: ProtocolVersion::V1_0,
            id: response_id,
            outcome,
        }
    }

    /// Parse one JSON line into a protocol request and return a response.
    pub async fn handle_line(&self, line: &str) -> OracleResponse {
        match serde_json::from_str::<OracleRequest>(line) {
            Ok(request) => self.handle_request(request).await,
            Err(_) => OracleResponse {
                version: ProtocolVersion::V1_0,
                id: None,
                outcome: OracleOutcome::Error {
                    error: GatewayError::new(
                        GatewayErrorCode::InvalidRequest,
                        false,
                        Some("invalid request JSON".to_string()),
                    ),
                },
            },
        }
    }

    /// Serve newline-delimited requests from `reader` and write one response line per request.
    ///
    /// Empty and whitespace-only lines are ignored.
    pub async fn serve<R, W>(&self, reader: R, mut writer: W) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut lines = BufReader::new(reader).lines();

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }

            let response = self.handle_line(&line).await;
            let encoded = serde_json::to_vec(&response)
                .expect("oracle responses must always be serializable");
            writer.write_all(&encoded).await?;
            writer.write_all(b"\n").await?;
            writer.flush().await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use krusty_kms_common::ChainId;
    use krusty_kms_domain::{
        AccountClassKind, AccountClassSpec, CacheMetadata, CachePolicy, CacheStatus,
        DeploymentState, DerivationPath, FeltHex, HexBytes, KeyDomain, OperationId, OperationKind,
        OperationState, OperationStatus, Provenance, QueryMode, RawMessagePayload, RequestId,
        SaltPolicySpec, SecretRef, SignResult, SnapshotBlockMetadata, TokenBalanceSnapshot,
        TrackedToken,
    };
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use tokio::io::{duplex, AsyncReadExt};

    struct FakeHandler {
        statuses: Mutex<VecDeque<Option<OperationStatus>>>,
    }

    impl FakeHandler {
        fn new() -> Self {
            Self {
                statuses: Mutex::new(VecDeque::from([Some(sample_operation(
                    "op-1",
                    OperationKind::QueryAccountSnapshot,
                ))])),
            }
        }
    }

    #[async_trait]
    impl OracleHandler for FakeHandler {
        async fn derive_account(
            &self,
            _request: DerivationRequest,
        ) -> Result<TrackedCommandResult<AccountDescriptor>, GatewayError> {
            Ok(TrackedCommandResult {
                operation: sample_operation("derive-1", OperationKind::DeriveAccount),
                value: sample_account_descriptor(),
            })
        }

        async fn check_deployment(
            &self,
            _request: DerivationRequest,
        ) -> Result<TrackedCommandResult<CheckDeploymentResult>, GatewayError> {
            Ok(TrackedCommandResult {
                operation: sample_operation("check-1", OperationKind::CheckDeployment),
                value: CheckDeploymentResult {
                    account: sample_account_descriptor(),
                    deployment: DeploymentState::Deployed,
                },
            })
        }

        async fn deploy_account(
            &self,
            _request: DeployAccountRequest,
        ) -> Result<TrackedCommandResult<DeployAccountResult>, GatewayError> {
            Ok(TrackedCommandResult {
                operation: sample_operation("deploy-1", OperationKind::DeployAccount),
                value: DeployAccountResult {
                    account: sample_account_descriptor(),
                    deployment: DeploymentState::Deploying {
                        tx_hash: FeltHex::parse("0xabc").unwrap(),
                    },
                    already_deployed: false,
                },
            })
        }

        async fn sign(
            &self,
            request: SignRequest,
        ) -> Result<TrackedCommandResult<SignResult>, GatewayError> {
            let key_domain = request.key_domain();
            let derivation_path = request.derivation_path();
            Ok(TrackedCommandResult {
                operation: match key_domain {
                    KeyDomain::NostrEvent => OperationStatus {
                        id: OperationId::new("sign-1").unwrap(),
                        kind: OperationKind::Sign,
                        state: OperationState::Accepted { tx_hash: None },
                        provenance: None,
                    },
                    KeyDomain::StarknetAccount | KeyDomain::TongoAccount => OperationStatus {
                        id: OperationId::new("sign-stark-1").unwrap(),
                        kind: OperationKind::Sign,
                        state: OperationState::Accepted { tx_hash: None },
                        provenance: Some(Provenance {
                            chain_id: ChainId::Sepolia,
                            key_domain,
                            derivation_path,
                            class_hash: None,
                        }),
                    },
                },
                value: match key_domain {
                    KeyDomain::NostrEvent => SignResult::NostrBip340 {
                        public_key: HexBytes::parse(
                            "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
                        )
                        .unwrap(),
                        signature: HexBytes::parse(
                            "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
                        )
                        .unwrap(),
                    },
                    KeyDomain::StarknetAccount | KeyDomain::TongoAccount => {
                        SignResult::StarkEcdsa {
                            public_key: FeltHex::parse("0x456").unwrap(),
                            signature_r: FeltHex::parse("0x111").unwrap(),
                            signature_s: FeltHex::parse("0x222").unwrap(),
                        }
                    }
                },
            })
        }

        async fn query_account_snapshot(
            &self,
            request: krusty_kms_domain::AccountSnapshotRequest,
        ) -> Result<TrackedCommandResult<AccountSnapshot>, GatewayError> {
            Ok(TrackedCommandResult {
                operation: sample_operation("snapshot-1", OperationKind::QueryAccountSnapshot),
                value: AccountSnapshot {
                    address: request.address,
                    deployment: DeploymentState::Deployed,
                    nonce: Some(FeltHex::parse("0x9").unwrap()),
                    balances: vec![TokenBalanceSnapshot {
                        token: TrackedToken {
                            symbol: "STRK".to_string(),
                            address: FeltHex::parse("0x456").unwrap(),
                            decimals: 18,
                        },
                        amount_raw: "42".to_string(),
                    }],
                    block: SnapshotBlockMetadata {
                        selector: krusty_kms_domain::BlockSelector::Latest,
                        block_hash: Some(FeltHex::parse("0xdead").unwrap()),
                        block_number: Some(55),
                    },
                    cache: CacheMetadata {
                        status: CacheStatus::Miss,
                        generated_at_ms: 10,
                        age_ms: 0,
                    },
                },
            })
        }

        async fn get_operation_status(
            &self,
            _request: krusty_kms_domain::GetOperationStatusRequest,
        ) -> Result<OperationLookupResult, GatewayError> {
            Ok(OperationLookupResult {
                operation: self.statuses.lock().unwrap().pop_front().flatten(),
            })
        }
    }

    fn sample_operation(id: &str, kind: OperationKind) -> OperationStatus {
        OperationStatus {
            id: OperationId::new(id).unwrap(),
            kind,
            state: OperationState::Accepted { tx_hash: None },
            provenance: Some(Provenance {
                chain_id: ChainId::Sepolia,
                key_domain: KeyDomain::StarknetAccount,
                derivation_path: DerivationPath {
                    coin_type: 9004,
                    account_index: 0,
                    address_index: 0,
                },
                class_hash: Some(FeltHex::parse("0x111").unwrap()),
            }),
        }
    }

    fn sample_account_descriptor() -> AccountDescriptor {
        AccountDescriptor {
            address: FeltHex::parse("0x123").unwrap(),
            public_key: FeltHex::parse("0x456").unwrap(),
            class_hash: FeltHex::parse("0x789").unwrap(),
            salt: FeltHex::parse("0x456").unwrap(),
            constructor_calldata: vec![FeltHex::parse("0x456").unwrap()],
            deployer_address: FeltHex::parse("0x0").unwrap(),
            provenance: Provenance {
                chain_id: ChainId::Sepolia,
                key_domain: KeyDomain::StarknetAccount,
                derivation_path: DerivationPath {
                    coin_type: 9004,
                    account_index: 0,
                    address_index: 0,
                },
                class_hash: Some(FeltHex::parse("0x789").unwrap()),
            },
        }
    }

    fn sample_derivation_request() -> DerivationRequest {
        DerivationRequest {
            secret: SecretRef::new("wallet-1").unwrap(),
            key_domain: KeyDomain::StarknetAccount,
            chain_id: ChainId::Sepolia,
            path: DerivationPath {
                coin_type: 9004,
                account_index: 0,
                address_index: 0,
            },
            account_class: AccountClassSpec {
                kind: AccountClassKind::OpenZeppelin,
                class_hash: None,
                source_label: None,
            },
            salt_policy: SaltPolicySpec::PublicKey,
        }
    }

    fn sample_sign_request() -> SignRequest {
        SignRequest::NostrEvent {
            secret: SecretRef::new("nostr-secret").unwrap(),
            derivation_path: DerivationPath {
                coin_type: 1237,
                account_index: 0,
                address_index: 7,
            },
            event_id: HexBytes::parse(
                "6c3fd336b5457a0f2b74959f177a5c5e7f9ab75cdb4ab7a3ec7aaf1e2a3d2b13",
            )
            .unwrap(),
        }
    }

    fn sample_stark_sign_request() -> SignRequest {
        SignRequest::StarkHash {
            secret: SecretRef::new("stark-secret").unwrap(),
            key_domain: krusty_kms_domain::StarkKeyDomain::StarknetAccount,
            derivation_path: DerivationPath {
                coin_type: 9004,
                account_index: 0,
                address_index: 3,
            },
            chain_id: ChainId::Sepolia,
            domain: krusty_kms_domain::StarkSignDomain::TransactionHash,
            hash: FeltHex::parse("0x1234").unwrap(),
        }
    }

    fn sample_raw_nostr_sign_request() -> SignRequest {
        SignRequest::NostrRawMessage {
            secret: SecretRef::new("nostr-secret").unwrap(),
            derivation_path: DerivationPath {
                coin_type: 1237,
                account_index: 0,
                address_index: 7,
            },
            payload: RawMessagePayload::Utf8("hello nostr".to_string()),
        }
    }

    #[tokio::test]
    async fn handle_request_dispatches_derive_account() {
        let oracle = StdioOracle::new(FakeHandler::new());
        let response = oracle
            .handle_request(OracleRequest {
                version: ProtocolVersion::V1_0,
                id: RequestId::new("req-1").unwrap(),
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
            command: OracleCommand::GetOperationStatus(
                krusty_kms_domain::GetOperationStatusRequest {
                    operation_id: OperationId::new("op-1").unwrap(),
                },
            ),
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
                OracleResult::GetOperationStatus(result) => {
                    assert_eq!(result.operation.unwrap().id.as_str(), "op-1");
                }
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
    async fn sign_command_dispatches_domain_payloads() {
        let oracle = StdioOracle::new(FakeHandler::new());
        let response = oracle
            .handle_request(OracleRequest {
                version: ProtocolVersion::V1_0,
                id: RequestId::new("req-sign").unwrap(),
                command: OracleCommand::Sign(sample_sign_request()),
            })
            .await;

        match response.outcome {
            OracleOutcome::Ok { result } => match *result {
                OracleResult::Sign(result) => {
                    assert_eq!(result.operation.id.as_str(), "sign-1");
                    match result.value {
                        SignResult::NostrBip340 {
                            public_key,
                            signature,
                        } => {
                            assert_eq!(public_key.as_str().len(), 64);
                            assert_eq!(signature.as_str().len(), 128);
                        }
                        other => panic!("unexpected sign result: {other:?}"),
                    }
                }
                other => panic!("unexpected response: {:?}", other),
            },
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn sign_command_supports_raw_nostr_payloads() {
        let oracle = StdioOracle::new(FakeHandler::new());
        let response = oracle
            .handle_request(OracleRequest {
                version: ProtocolVersion::V1_0,
                id: RequestId::new("req-sign-raw").unwrap(),
                command: OracleCommand::Sign(sample_raw_nostr_sign_request()),
            })
            .await;

        match response.outcome {
            OracleOutcome::Ok { result } => match *result {
                OracleResult::Sign(result) => {
                    assert_eq!(result.operation.id.as_str(), "sign-1");
                    match result.value {
                        SignResult::NostrBip340 {
                            public_key,
                            signature,
                        } => {
                            assert_eq!(public_key.as_str().len(), 64);
                            assert_eq!(signature.as_str().len(), 128);
                        }
                        other => panic!("unexpected sign result: {other:?}"),
                    }
                }
                other => panic!("unexpected response: {:?}", other),
            },
            other => panic!("unexpected response: {:?}", other),
        }
    }

    #[tokio::test]
    async fn sign_command_supports_stark_result_shape() {
        let oracle = StdioOracle::new(FakeHandler::new());
        let response = oracle
            .handle_request(OracleRequest {
                version: ProtocolVersion::V1_0,
                id: RequestId::new("req-sign-stark").unwrap(),
                command: OracleCommand::Sign(sample_stark_sign_request()),
            })
            .await;

        match response.outcome {
            OracleOutcome::Ok { result } => match *result {
                OracleResult::Sign(result) => {
                    assert_eq!(result.operation.id.as_str(), "sign-stark-1");
                    match result.value {
                        SignResult::StarkEcdsa {
                            public_key,
                            signature_r,
                            signature_s,
                        } => {
                            assert!(public_key.as_str().starts_with("0x"));
                            assert!(signature_r.as_str().starts_with("0x"));
                            assert!(signature_s.as_str().starts_with("0x"));
                        }
                        other => panic!("unexpected sign result: {other:?}"),
                    }
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
}
