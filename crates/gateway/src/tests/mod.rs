mod flows;
mod policies;

use crate::{
    Clock, DeployExecution, Gateway, GatewayBackend, GatewayResult, OperationRetentionPolicy,
    SecretResolver,
};
use async_trait::async_trait;
use krusty_kms_common::{ChainId, SecretFelt};
use krusty_kms_domain::{
    AccountClassKind, AccountClassSpec, AccountDescriptor, AccountSnapshotRequest, BlockSelector,
    CachePolicy, DeployMode, DerivationRequest, FeltHex, HexBytes, KeyDomain, QueryMode,
    RawMessagePayload, SaltPolicySpec, SignRequest, SnapshotBlockMetadata,
};
use starknet_types_core::felt::Felt;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use zeroize::Zeroizing;

#[derive(Default)]
struct TestClock {
    now_ms: AtomicU64,
}

impl TestClock {
    fn set(&self, value: u64) {
        self.now_ms.store(value, Ordering::Relaxed);
    }
}

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::Relaxed)
    }
}

struct FixedSecretResolver {
    private_key: SecretFelt,
    nostr_private_key: [u8; 32],
}

#[async_trait]
impl SecretResolver for FixedSecretResolver {
    async fn resolve_private_key(
        &self,
        _secret: &krusty_kms_domain::SecretRef,
        _key_domain: KeyDomain,
        _path: krusty_kms_domain::DerivationPath,
    ) -> GatewayResult<SecretFelt> {
        Ok(self.private_key.clone())
    }

    async fn resolve_nostr_private_key(
        &self,
        _secret: &krusty_kms_domain::SecretRef,
        _path: krusty_kms_domain::DerivationPath,
    ) -> GatewayResult<Zeroizing<[u8; 32]>> {
        Ok(Zeroizing::new(self.nostr_private_key))
    }
}

struct FakeBackend {
    chain_id: ChainId,
    deployed: bool,
    nonce: FeltHex,
    balances: BTreeMap<String, String>,
    block: SnapshotBlockMetadata,
    deploy_execution: Mutex<DeployExecution>,
    deployment_checks: AtomicUsize,
    nonce_reads: AtomicUsize,
    balance_reads: AtomicUsize,
    block_reads: AtomicUsize,
}

#[async_trait]
impl GatewayBackend for FakeBackend {
    fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    async fn check_deployed(
        &self,
        _address: &FeltHex,
        _block: &BlockSelector,
    ) -> GatewayResult<bool> {
        self.deployment_checks.fetch_add(1, Ordering::Relaxed);
        Ok(self.deployed)
    }

    async fn deploy_open_zeppelin(
        &self,
        _private_key: &SecretFelt,
        _account: &AccountDescriptor,
        _mode: DeployMode,
    ) -> GatewayResult<DeployExecution> {
        Ok(self.deploy_execution.lock().unwrap().clone())
    }

    async fn nonce(
        &self,
        _address: &FeltHex,
        _block: &BlockSelector,
    ) -> GatewayResult<FeltHex> {
        self.nonce_reads.fetch_add(1, Ordering::Relaxed);
        Ok(self.nonce.clone())
    }

    async fn token_balance(
        &self,
        _address: &FeltHex,
        token: &krusty_kms_domain::TrackedToken,
        _block: &BlockSelector,
    ) -> GatewayResult<String> {
        self.balance_reads.fetch_add(1, Ordering::Relaxed);
        Ok(self
            .balances
            .get(&token.symbol)
            .cloned()
            .unwrap_or_default())
    }

    async fn block_metadata(
        &self,
        _block: &BlockSelector,
    ) -> GatewayResult<SnapshotBlockMetadata> {
        self.block_reads.fetch_add(1, Ordering::Relaxed);
        Ok(self.block.clone())
    }
}

fn gateway(
    clock: TestClock,
    deploy_execution: DeployExecution,
) -> Gateway<FakeBackend, FixedSecretResolver, TestClock> {
    gateway_with_retention(clock, deploy_execution, OperationRetentionPolicy::default())
}

fn gateway_with_retention(
    clock: TestClock,
    deploy_execution: DeployExecution,
    retention: OperationRetentionPolicy,
) -> Gateway<FakeBackend, FixedSecretResolver, TestClock> {
    Gateway::with_clock_and_retention(
        FakeBackend {
            chain_id: ChainId::Sepolia,
            deployed: true,
            nonce: FeltHex::parse("0x11").unwrap(),
            balances: BTreeMap::from([("STRK".to_string(), "42".to_string())]),
            block: SnapshotBlockMetadata {
                selector: BlockSelector::Latest,
                block_hash: Some(FeltHex::parse("0xabc").unwrap()),
                block_number: Some(100),
            },
            deploy_execution: Mutex::new(deploy_execution),
            deployment_checks: AtomicUsize::new(0),
            nonce_reads: AtomicUsize::new(0),
            balance_reads: AtomicUsize::new(0),
            block_reads: AtomicUsize::new(0),
        },
        FixedSecretResolver {
            private_key: SecretFelt::new(Felt::from(123u64)),
            nostr_private_key: [
                0x1d, 0xce, 0x8d, 0x2e, 0xc6, 0x18, 0x4c, 0xca, 0x94, 0x33, 0xf8, 0xf7, 0xb2,
                0x70, 0x2d, 0x90, 0x14, 0x93, 0x66, 0x27, 0xce, 0x0f, 0x50, 0x92, 0x6f, 0x47,
                0x1e, 0x52, 0x94, 0x6d, 0x0f, 0x4c,
            ],
        },
        clock,
        retention,
    )
}

fn derivation_request() -> DerivationRequest {
    DerivationRequest {
        secret: krusty_kms_domain::SecretRef::new("demo-secret").unwrap(),
        key_domain: KeyDomain::StarknetAccount,
        chain_id: ChainId::Sepolia,
        path: krusty_kms_domain::DerivationPath {
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

fn snapshot_request(mode: QueryMode) -> AccountSnapshotRequest {
    AccountSnapshotRequest {
        chain_id: ChainId::Sepolia,
        address: FeltHex::parse("0x123").unwrap(),
        tokens: vec![krusty_kms_domain::TrackedToken {
            symbol: "STRK".to_string(),
            address: FeltHex::parse("0x456").unwrap(),
            decimals: 18,
        }],
        block: BlockSelector::Latest,
        mode,
        cache_policy: CachePolicy::new(1_000, 5_000, 8).unwrap(),
    }
}

fn nostr_sign_request() -> SignRequest {
    SignRequest::NostrEvent {
        secret: krusty_kms_domain::SecretRef::new("nostr-secret").unwrap(),
        derivation_path: krusty_kms_domain::DerivationPath {
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

fn raw_nostr_sign_request() -> SignRequest {
    SignRequest::NostrRawMessage {
        secret: krusty_kms_domain::SecretRef::new("nostr-secret").unwrap(),
        derivation_path: krusty_kms_domain::DerivationPath {
            coin_type: 1237,
            account_index: 0,
            address_index: 7,
        },
        payload: RawMessagePayload::Utf8("hello nostr".to_string()),
    }
}

fn stark_sign_request() -> SignRequest {
    SignRequest::StarkHash {
        secret: krusty_kms_domain::SecretRef::new("stark-secret").unwrap(),
        key_domain: krusty_kms_domain::StarkKeyDomain::StarknetAccount,
        derivation_path: krusty_kms_domain::DerivationPath {
            coin_type: 9004,
            account_index: 0,
            address_index: 2,
        },
        chain_id: ChainId::Sepolia,
        domain: krusty_kms_domain::StarkSignDomain::TransactionHash,
        hash: FeltHex::parse("0x1234").unwrap(),
        allow_raw_stark_hash: true,
    }
}
