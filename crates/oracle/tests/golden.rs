use async_trait::async_trait;
use krusty_kms_common::ChainId;
use krusty_kms_domain::{
    AccountDescriptor, CheckDeploymentResult, DerivationPath, DerivationRequest, FeltHex,
    GatewayError, HexBytes, OperationLookupResult, OperationStatus, ProtocolInfo, RequestId,
    SignRequest, SignResult, TrackedCommandResult,
};
use krusty_kms_oracle::{OracleHandler, StdioOracle};

struct GoldenHandler;

#[async_trait]
impl OracleHandler for GoldenHandler {
    async fn derive_account(
        &self,
        _request: DerivationRequest,
    ) -> Result<TrackedCommandResult<AccountDescriptor>, GatewayError> {
        Ok(TrackedCommandResult {
            operation: sample_operation(
                "derive-1",
                krusty_kms_domain::OperationKind::DeriveAccount,
            ),
            value: sample_account_descriptor(),
        })
    }

    async fn check_deployment(
        &self,
        _request: DerivationRequest,
    ) -> Result<TrackedCommandResult<CheckDeploymentResult>, GatewayError> {
        unreachable!("golden tests do not exercise check_deployment")
    }

    async fn deploy_account(
        &self,
        _request: krusty_kms_domain::DeployAccountRequest,
    ) -> Result<TrackedCommandResult<krusty_kms_domain::DeployAccountResult>, GatewayError> {
        unreachable!("golden tests do not exercise deploy_account")
    }

    async fn sign(
        &self,
        request: SignRequest,
    ) -> Result<TrackedCommandResult<SignResult>, GatewayError> {
        let key_domain = request.key_domain();
        let derivation_path = request.derivation_path();
        Ok(TrackedCommandResult {
            operation: match key_domain {
                krusty_kms_domain::KeyDomain::NostrEvent => OperationStatus {
                    id: krusty_kms_domain::OperationId::new("sign-1").unwrap(),
                    kind: krusty_kms_domain::OperationKind::Sign,
                    state: krusty_kms_domain::OperationState::Completed,
                    provenance: None,
                },
                krusty_kms_domain::KeyDomain::StarknetAccount
                | krusty_kms_domain::KeyDomain::TongoAccount => OperationStatus {
                    id: krusty_kms_domain::OperationId::new("sign-stark-1").unwrap(),
                    kind: krusty_kms_domain::OperationKind::Sign,
                    state: krusty_kms_domain::OperationState::Completed,
                    provenance: Some(krusty_kms_domain::Provenance {
                        chain_id: ChainId::Sepolia,
                        key_domain,
                        derivation_path,
                        class_hash: None,
                    }),
                },
            },
            value: match key_domain {
                krusty_kms_domain::KeyDomain::NostrEvent => SignResult::NostrBip340 {
                    public_key: HexBytes::parse(
                        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
                    )
                    .unwrap(),
                    signature: HexBytes::parse(
                        "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
                    )
                    .unwrap(),
                },
                krusty_kms_domain::KeyDomain::StarknetAccount
                | krusty_kms_domain::KeyDomain::TongoAccount => SignResult::StarkEcdsa {
                    public_key: FeltHex::parse("0x456").unwrap(),
                    signature_r: FeltHex::parse("0x111").unwrap(),
                    signature_s: FeltHex::parse("0x222").unwrap(),
                },
            },
        })
    }

    async fn query_account_snapshot(
        &self,
        _request: krusty_kms_domain::AccountSnapshotRequest,
    ) -> Result<TrackedCommandResult<krusty_kms_domain::AccountSnapshot>, GatewayError> {
        unreachable!("golden tests do not exercise query_account_snapshot")
    }

    async fn get_operation_status(
        &self,
        _request: krusty_kms_domain::GetOperationStatusRequest,
    ) -> Result<OperationLookupResult, GatewayError> {
        unreachable!("golden tests do not exercise get_operation_status")
    }
}

fn sample_operation(id: &str, kind: krusty_kms_domain::OperationKind) -> OperationStatus {
    OperationStatus {
        id: krusty_kms_domain::OperationId::new(id).unwrap(),
        kind,
        state: krusty_kms_domain::OperationState::Completed,
        provenance: Some(krusty_kms_domain::Provenance {
            chain_id: ChainId::Sepolia,
            key_domain: krusty_kms_domain::KeyDomain::StarknetAccount,
            derivation_path: DerivationPath {
                coin_type: 9004,
                account_index: 0,
                address_index: 0,
            },
            class_hash: Some(FeltHex::parse("0x789").unwrap()),
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
        provenance: krusty_kms_domain::Provenance {
            chain_id: ChainId::Sepolia,
            key_domain: krusty_kms_domain::KeyDomain::StarknetAccount,
            derivation_path: DerivationPath {
                coin_type: 9004,
                account_index: 0,
                address_index: 0,
            },
            class_hash: Some(FeltHex::parse("0x789").unwrap()),
        },
    }
}

fn normalize_fixture_json(input: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(input).unwrap();
    serde_json::to_string_pretty(&value).unwrap()
}

async fn assert_valid_request_fixture(request_fixture: &str, response_fixture: &str) {
    let oracle = StdioOracle::new(GoldenHandler);
    let response = oracle.handle_line(request_fixture).await;
    let actual = normalize_fixture_json(&serde_json::to_string(&response).unwrap());
    let expected = normalize_fixture_json(response_fixture);

    assert_eq!(actual, expected);
}

#[tokio::test]
async fn protocol_info_fixture_matches_wire_shape() {
    assert_valid_request_fixture(
        include_str!("fixtures/protocol_info.request.json"),
        include_str!("fixtures/protocol_info.response.json"),
    )
    .await;
}

#[tokio::test]
async fn derive_account_fixture_matches_wire_shape() {
    assert_valid_request_fixture(
        include_str!("fixtures/derive_account.request.json"),
        include_str!("fixtures/derive_account.response.json"),
    )
    .await;
}

#[tokio::test]
async fn sign_fixture_matches_wire_shape() {
    assert_valid_request_fixture(
        include_str!("fixtures/sign.request.json"),
        include_str!("fixtures/sign.response.json"),
    )
    .await;
}

#[tokio::test]
async fn sign_stark_fixture_matches_wire_shape() {
    assert_valid_request_fixture(
        include_str!("fixtures/sign_stark.request.json"),
        include_str!("fixtures/sign_stark.response.json"),
    )
    .await;
}

#[tokio::test]
async fn invalid_request_fixture_matches_wire_shape() {
    let oracle = StdioOracle::new(GoldenHandler);
    let response = oracle
        .handle_line(include_str!("fixtures/invalid_request.txt"))
        .await;
    let actual = normalize_fixture_json(&serde_json::to_string(&response).unwrap());
    let expected = normalize_fixture_json(include_str!("fixtures/invalid_request.response.json"));

    assert_eq!(actual, expected);
}

#[test]
fn protocol_info_lists_sign_command() {
    let info = ProtocolInfo::stdio_v1();

    assert!(info
        .commands
        .contains(&krusty_kms_domain::OracleCommandName::Sign));
}

#[test]
fn request_fixture_examples_parse_as_domain_requests() {
    let derive: krusty_kms_domain::OracleRequest =
        serde_json::from_str(include_str!("fixtures/derive_account.request.json")).unwrap();
    let sign: krusty_kms_domain::OracleRequest =
        serde_json::from_str(include_str!("fixtures/sign.request.json")).unwrap();
    let sign_stark: krusty_kms_domain::OracleRequest =
        serde_json::from_str(include_str!("fixtures/sign_stark.request.json")).unwrap();

    assert_eq!(derive.id, RequestId::new("req-derive").unwrap());
    assert_eq!(sign.id, RequestId::new("req-sign").unwrap());
    assert_eq!(sign_stark.id, RequestId::new("req-sign-stark").unwrap());
}
