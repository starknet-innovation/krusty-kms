//! Sign dispatch and the `KRUSTY_ORACLE_REQUIRE_CONFIRM` privilege gate.

use super::fixtures::{
    sample_derivation_request, sample_raw_nostr_sign_request, sample_sign_request,
    sample_stark_sign_request, FakeHandler,
};
use crate::StdioOracle;
use krusty_kms_domain::{
    DeployAccountRequest, DeployMode, GatewayErrorCode, OracleCommand, OracleOutcome,
    OracleRequest, OracleResult, ProtocolVersion, RequestId, SignResult,
};

static CONFIRM_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Serializes tests that depend on (or must not see) `KRUSTY_ORACLE_REQUIRE_CONFIRM`.
struct ConfirmEnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl ConfirmEnvGuard {
    fn acquire() -> Self {
        let guard = Self {
            _lock: CONFIRM_ENV_LOCK.lock().unwrap(),
        };
        // Clear any leftover value from a panicked peer before continuing.
        std::env::remove_var("KRUSTY_ORACLE_REQUIRE_CONFIRM");
        guard
    }

    fn require_confirm() -> Self {
        let guard = Self::acquire();
        std::env::set_var("KRUSTY_ORACLE_REQUIRE_CONFIRM", "1");
        guard
    }
}

impl Drop for ConfirmEnvGuard {
    fn drop(&mut self) {
        std::env::remove_var("KRUSTY_ORACLE_REQUIRE_CONFIRM");
    }
}

#[tokio::test]
async fn sign_command_dispatches_domain_payloads() {
    let _env = ConfirmEnvGuard::acquire();
    let oracle = StdioOracle::new(FakeHandler::new());
    let response = oracle
        .handle_request(OracleRequest {
            version: ProtocolVersion::V1_0,
            id: RequestId::new("req-sign").unwrap(),
            confirm: false,
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
    let _env = ConfirmEnvGuard::acquire();
    let oracle = StdioOracle::new(FakeHandler::new());
    let response = oracle
        .handle_request(OracleRequest {
            version: ProtocolVersion::V1_0,
            id: RequestId::new("req-sign-raw").unwrap(),
            confirm: false,
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
    let _env = ConfirmEnvGuard::acquire();
    let oracle = StdioOracle::new(FakeHandler::new());
    let response = oracle
        .handle_request(OracleRequest {
            version: ProtocolVersion::V1_0,
            id: RequestId::new("req-sign-stark").unwrap(),
            confirm: false,
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
async fn confirm_gate_rejects_privileged_ops_without_confirm() {
    let _env = ConfirmEnvGuard::require_confirm();

    let oracle = StdioOracle::new(FakeHandler::new());
    let response = oracle
        .handle_request(OracleRequest {
            version: ProtocolVersion::V1_0,
            id: RequestId::new("req-confirm-sign").unwrap(),
            confirm: false,
            command: OracleCommand::Sign(sample_stark_sign_request()),
        })
        .await;

    match response.outcome {
        OracleOutcome::Error { error } => {
            assert_eq!(error.code, GatewayErrorCode::InvalidRequest);
            assert!(
                error
                    .message
                    .as_deref()
                    .unwrap_or("")
                    .contains("confirm=true"),
                "unexpected message: {:?}",
                error.message
            );
        }
        other => panic!("expected confirm rejection, got {other:?}"),
    }

    let deploy = oracle
        .handle_request(OracleRequest {
            version: ProtocolVersion::V1_0,
            id: RequestId::new("req-confirm-deploy").unwrap(),
            confirm: false,
            command: OracleCommand::DeployAccount(DeployAccountRequest {
                derivation: sample_derivation_request(),
                mode: DeployMode::SubmitOnly,
            }),
        })
        .await;
    assert!(matches!(deploy.outcome, OracleOutcome::Error { .. }));

    // Non-privileged commands remain allowed without confirm.
    let info = oracle
        .handle_request(OracleRequest {
            version: ProtocolVersion::V1_0,
            id: RequestId::new("req-confirm-info").unwrap(),
            confirm: false,
            command: OracleCommand::GetProtocolInfo,
        })
        .await;
    assert!(matches!(info.outcome, OracleOutcome::Ok { .. }));
}

#[tokio::test]
async fn confirm_gate_allows_privileged_ops_with_confirm() {
    let _env = ConfirmEnvGuard::require_confirm();

    let oracle = StdioOracle::new(FakeHandler::new());
    let response = oracle
        .handle_request(OracleRequest {
            version: ProtocolVersion::V1_0,
            id: RequestId::new("req-confirm-ok").unwrap(),
            confirm: true,
            command: OracleCommand::Sign(sample_stark_sign_request()),
        })
        .await;
    assert!(matches!(response.outcome, OracleOutcome::Ok { .. }));
}
