use crate::{
    AccountDescriptor, AccountSnapshot, CheckDeploymentResult, DeployAccountRequest,
    DeployAccountResult, DerivationRequest, GatewayError, OperationId, OperationStatus,
    ProtocolVersion, SignRequest, SignResult,
};
use serde::{Deserialize, Serialize};

/// Stable request correlation id for the oracle transport.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RequestId(String);

impl RequestId {
    pub fn new(value: impl Into<String>) -> Result<Self, crate::DomainError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(crate::DomainError::EmptyField {
                field: "request_id",
            });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RequestId {
    type Error = crate::DomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<RequestId> for String {
    fn from(value: RequestId) -> Self {
        value.0
    }
}

/// Request for retrieving the latest known status of an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetOperationStatusRequest {
    pub operation_id: OperationId,
}

/// Supported oracle commands for stdio protocol V1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", content = "params", rename_all = "snake_case")]
pub enum OracleCommand {
    GetProtocolInfo,
    DeriveAccount(DerivationRequest),
    CheckDeployment(DerivationRequest),
    DeployAccount(DeployAccountRequest),
    Sign(SignRequest),
    QueryAccountSnapshot(crate::AccountSnapshotRequest),
    GetOperationStatus(GetOperationStatusRequest),
}

/// One stdio oracle request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleRequest {
    pub version: ProtocolVersion,
    pub id: RequestId,
    #[serde(flatten)]
    pub command: OracleCommand,
}

/// Machine-readable command names exposed by the current protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleCommandName {
    GetProtocolInfo,
    DeriveAccount,
    CheckDeployment,
    DeployAccount,
    Sign,
    QueryAccountSnapshot,
    GetOperationStatus,
}

/// Protocol metadata returned by `get_protocol_info`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolInfo {
    pub version: ProtocolVersion,
    pub transport: String,
    pub commands: Vec<OracleCommandName>,
}

impl ProtocolInfo {
    pub fn stdio_v1() -> Self {
        Self {
            version: ProtocolVersion::V1_0,
            transport: "stdio-jsonl".to_string(),
            commands: vec![
                OracleCommandName::GetProtocolInfo,
                OracleCommandName::DeriveAccount,
                OracleCommandName::CheckDeployment,
                OracleCommandName::DeployAccount,
                OracleCommandName::Sign,
                OracleCommandName::QueryAccountSnapshot,
                OracleCommandName::GetOperationStatus,
            ],
        }
    }
}

/// Successful result wrapper for gateway-backed oracle commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackedCommandResult<T> {
    pub operation: OperationStatus,
    pub value: T,
}

/// Result wrapper for the `get_operation_status` oracle command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum OperationLookupResult {
    Found { operation: OperationStatus },
    NotFound { operation_id: OperationId },
}

/// Successful oracle response payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum OracleResult {
    ProtocolInfo(ProtocolInfo),
    DeriveAccount(TrackedCommandResult<AccountDescriptor>),
    CheckDeployment(TrackedCommandResult<CheckDeploymentResult>),
    DeployAccount(TrackedCommandResult<DeployAccountResult>),
    Sign(TrackedCommandResult<SignResult>),
    QueryAccountSnapshot(TrackedCommandResult<AccountSnapshot>),
    GetOperationStatus(OperationLookupResult),
}

/// Response outcome for a single oracle request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum OracleOutcome {
    Ok { result: Box<OracleResult> },
    Error { error: GatewayError },
}

/// One stdio oracle response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleResponse {
    pub version: ProtocolVersion,
    pub id: Option<RequestId>,
    #[serde(flatten)]
    pub outcome: OracleOutcome,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccountClassKind, AccountClassSpec, ChainId, DerivationPath, HexBytes, KeyDomain,
        SaltPolicySpec, SecretRef,
    };

    #[test]
    fn request_id_rejects_blank_values() {
        assert!(RequestId::new("   ").is_err());
    }

    #[test]
    fn oracle_request_roundtrips_with_tagged_command() {
        let request = OracleRequest {
            version: ProtocolVersion::V1_0,
            id: RequestId::new("req-1").unwrap(),
            command: OracleCommand::DeriveAccount(DerivationRequest {
                secret: SecretRef::new("wallet-1").unwrap(),
                key_domain: KeyDomain::StarknetAccount,
                chain_id: ChainId::Sepolia,
                path: DerivationPath {
                    coin_type: 9004,
                    account_index: 0,
                    address_index: 1,
                },
                account_class: AccountClassSpec {
                    kind: AccountClassKind::OpenZeppelin,
                    class_hash: None,
                    source_label: None,
                },
                salt_policy: SaltPolicySpec::PublicKey,
            }),
        };

        let json = serde_json::to_string(&request).unwrap();
        let roundtrip: OracleRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtrip, request);
        assert!(json.contains("\"command\":\"derive_account\""));
    }

    #[test]
    fn protocol_info_lists_supported_v1_commands() {
        let info = ProtocolInfo::stdio_v1();

        assert_eq!(info.version, ProtocolVersion::V1_0);
        assert_eq!(info.transport, "stdio-jsonl");
        assert_eq!(info.commands.len(), 7);
    }

    #[test]
    fn oracle_request_roundtrips_sign_command() {
        let request = OracleRequest {
            version: ProtocolVersion::V1_0,
            id: RequestId::new("req-sign").unwrap(),
            command: OracleCommand::Sign(SignRequest::NostrEvent {
                secret: SecretRef::new("nostr-secret").unwrap(),
                derivation_path: DerivationPath {
                    coin_type: 1237,
                    account_index: 0,
                    address_index: 9,
                },
                event_id: HexBytes::parse(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
                .unwrap(),
            }),
        };

        let json = serde_json::to_string(&request).unwrap();
        let roundtrip: OracleRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtrip, request);
        assert!(json.contains("\"command\":\"sign\""));
    }
}
