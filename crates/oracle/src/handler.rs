//! Effectful command surface consumed by the stdio transport, plus the
//! gateway-backed implementation.

use async_trait::async_trait;
use krusty_kms_domain::{
    AccountDescriptor, AccountSnapshot, CheckDeploymentResult, DeployAccountRequest,
    DeployAccountResult, DerivationRequest, GatewayError, OperationLookupResult, ProtocolInfo,
    SignRequest, SignResult, TrackedCommandResult,
};
use krusty_kms_gateway::{Clock, Gateway, GatewayBackend, GatewayResponse, SecretResolver};

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
        Ok(self.operation_status(&request.operation_id).await)
    }
}

fn tracked_result<T>(value: GatewayResponse<T>) -> TrackedCommandResult<T> {
    TrackedCommandResult {
        operation: value.operation,
        value: value.value,
    }
}
