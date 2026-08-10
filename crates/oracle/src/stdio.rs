//! Newline-delimited JSON stdio oracle server.

use crate::handler::OracleHandler;
use crate::line_reader::{read_line_limited, LimitedLine};
use krusty_kms_domain::{
    GatewayError, GatewayErrorCode, OracleCommand, OracleOutcome, OracleRequest, OracleResponse,
    OracleResult, ProtocolVersion,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// Maximum accepted stdio request line length (bytes). Larger lines are rejected.
const MAX_STDIO_LINE_BYTES: usize = 256 * 1024;

/// Newline-delimited JSON stdio oracle server.
///
/// # Trust model
///
/// The oracle does not authenticate callers and secret labels are global:
/// anyone who can write a request line can derive/sign/deploy with every
/// secret the wired-in handler resolves. Run it only behind a trusted peer
/// boundary (local supervisor, OS user isolation), never on a network socket.
/// See `docs/oracle-stdio-v1.md` § Trust Model.
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

        if let Some(error) = require_confirm_if_enabled(&request) {
            return OracleResponse {
                version: ProtocolVersion::V1_0,
                id: response_id,
                outcome: OracleOutcome::Error { error },
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
        if line.len() > MAX_STDIO_LINE_BYTES {
            return OracleResponse {
                version: ProtocolVersion::V1_0,
                id: None,
                outcome: OracleOutcome::Error {
                    error: GatewayError::new(
                        GatewayErrorCode::InvalidRequest,
                        false,
                        Some(format!(
                            "request line exceeds maximum length of {MAX_STDIO_LINE_BYTES} bytes"
                        )),
                    ),
                },
            };
        }

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
    /// Lines longer than [`MAX_STDIO_LINE_BYTES`] are rejected without parsing.
    /// The length limit is enforced **while reading** so oversized input cannot
    /// force unbounded allocation before rejection.
    pub async fn serve<R, W>(&self, reader: R, mut writer: W) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut reader = BufReader::new(reader);

        loop {
            match read_line_limited(&mut reader, MAX_STDIO_LINE_BYTES).await? {
                None => break,
                Some(LimitedLine::TooLong) => {
                    let response = OracleResponse {
                        version: ProtocolVersion::V1_0,
                        id: None,
                        outcome: OracleOutcome::Error {
                            error: GatewayError::new(
                                GatewayErrorCode::InvalidRequest,
                                false,
                                Some(format!(
                                    "request line exceeds maximum length of {MAX_STDIO_LINE_BYTES} bytes"
                                )),
                            ),
                        },
                    };
                    let encoded = serde_json::to_vec(&response)
                        .expect("oracle responses must always be serializable");
                    writer.write_all(&encoded).await?;
                    writer.write_all(b"\n").await?;
                    writer.flush().await?;
                }
                Some(LimitedLine::InvalidUtf8) => {
                    let response = OracleResponse {
                        version: ProtocolVersion::V1_0,
                        id: None,
                        outcome: OracleOutcome::Error {
                            error: GatewayError::new(
                                GatewayErrorCode::InvalidRequest,
                                false,
                                Some("request line is not valid UTF-8".to_string()),
                            ),
                        },
                    };
                    let encoded = serde_json::to_vec(&response)
                        .expect("oracle responses must always be serializable");
                    writer.write_all(&encoded).await?;
                    writer.write_all(b"\n").await?;
                    writer.flush().await?;
                }
                Some(LimitedLine::Complete(line)) => {
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
            }
        }

        Ok(())
    }
}

fn require_confirm_env_enabled() -> bool {
    match std::env::var("KRUSTY_ORACLE_REQUIRE_CONFIRM") {
        Ok(value) => matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"),
        Err(_) => false,
    }
}

/// When `KRUSTY_ORACLE_REQUIRE_CONFIRM=1`, privileged sign/deploy require `"confirm": true`.
fn require_confirm_if_enabled(request: &OracleRequest) -> Option<GatewayError> {
    if !require_confirm_env_enabled() {
        return None;
    }

    let privileged = matches!(
        request.command,
        OracleCommand::Sign(_) | OracleCommand::DeployAccount(_)
    );
    if privileged && !request.confirm {
        return Some(GatewayError::new(
            GatewayErrorCode::InvalidRequest,
            false,
            Some(
                "privileged command requires confirm=true when KRUSTY_ORACLE_REQUIRE_CONFIRM is set"
                    .to_string(),
            ),
        ));
    }
    None
}
