//! Shared fixtures: a fake oracle handler and sample request builders.

use crate::OracleHandler;
use async_trait::async_trait;
use krusty_kms_common::ChainId;
use krusty_kms_domain::{
    AccountClassKind, AccountClassSpec, AccountDescriptor, AccountSnapshot, CacheMetadata,
    CacheStatus, CheckDeploymentResult, DeployAccountRequest, DeployAccountResult,
    DeploymentState, DerivationPath, DerivationRequest, FeltHex, GatewayError, HexBytes,
    KeyDomain, OperationId, OperationKind, OperationLookupResult, OperationState, OperationStatus,
    Provenance, RawMessagePayload, SaltPolicySpec, SecretRef, SignRequest, SignResult,
    SnapshotBlockMetadata, TokenBalanceSnapshot, TrackedCommandResult, TrackedToken,
};
use std::collections::VecDeque;
use std::sync::Mutex;

pub(crate) struct FakeHandler {
    statuses: Mutex<VecDeque<Option<OperationStatus>>>,
}

impl FakeHandler {
    pub(crate) fn new() -> Self {
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
                    state: OperationState::Completed,
                    provenance: None,
                },
                KeyDomain::StarknetAccount | KeyDomain::TongoAccount => OperationStatus {
                    id: OperationId::new("sign-stark-1").unwrap(),
                    kind: OperationKind::Sign,
                    state: OperationState::Completed,
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
        Ok(match self.statuses.lock().unwrap().pop_front().flatten() {
            Some(operation) => OperationLookupResult::Found { operation },
            None => OperationLookupResult::NotFound {
                operation_id: OperationId::new("missing-op").unwrap(),
            },
        })
    }
}

pub(crate) fn sample_operation(id: &str, kind: OperationKind) -> OperationStatus {
    OperationStatus {
        id: OperationId::new(id).unwrap(),
        kind,
        state: OperationState::Completed,
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

pub(crate) fn sample_account_descriptor() -> AccountDescriptor {
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

pub(crate) fn sample_derivation_request() -> DerivationRequest {
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
            allow_unlisted_class_hash: false,
        },
        salt_policy: SaltPolicySpec::PublicKey,
    }
}

pub(crate) fn sample_sign_request() -> SignRequest {
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

pub(crate) fn sample_stark_sign_request() -> SignRequest {
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
        allow_raw_stark_hash: true,
    }
}

pub(crate) fn sample_raw_nostr_sign_request() -> SignRequest {
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
