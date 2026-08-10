//! Backend contract: the effectful boundary trait and its deploy result type.

use crate::GatewayResult;
use async_trait::async_trait;
use krusty_kms_common::{ChainId, SecretFelt};
use krusty_kms_domain::{
    AccountDescriptor, BlockSelector, DeployMode, FeltHex, SnapshotBlockMetadata, TrackedToken,
};

/// Runtime execution result for a deploy-account operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeployExecution {
    AlreadyDeployed,
    Submitted { tx_hash: FeltHex },
    Accepted { tx_hash: FeltHex },
}

/// Replaceable effectful boundary used by the gateway runtime.
#[async_trait]
pub trait GatewayBackend: Send + Sync {
    /// Chain this backend is configured for.
    fn chain_id(&self) -> ChainId;

    /// Check whether `address` is deployed at the selected block.
    async fn check_deployed(&self, address: &FeltHex, block: &BlockSelector)
        -> GatewayResult<bool>;

    /// Submit an OpenZeppelin account deployment, optionally waiting for receipt availability.
    async fn deploy_open_zeppelin(
        &self,
        private_key: &SecretFelt,
        account: &AccountDescriptor,
        mode: DeployMode,
    ) -> GatewayResult<DeployExecution>;

    /// Query the Starknet nonce for a deployed account.
    async fn nonce(&self, address: &FeltHex, block: &BlockSelector) -> GatewayResult<FeltHex>;

    /// Query the raw ERC-20 balance for one token.
    async fn token_balance(
        &self,
        address: &FeltHex,
        token: &TrackedToken,
        block: &BlockSelector,
    ) -> GatewayResult<String>;

    /// Resolve block metadata matching a selector.
    async fn block_metadata(&self, block: &BlockSelector) -> GatewayResult<SnapshotBlockMetadata>;
}
