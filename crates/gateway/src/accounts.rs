//! Account flows: derive, check deployment, and deploy.

use crate::backend::{DeployExecution, GatewayBackend};
use crate::clock::Clock;
use crate::gateway::Gateway;
use crate::types::{GatewayResponse, GatewayResult, SecretResolver};
use krusty_kms_domain::{
    AccountClassKind, AccountDescriptor, BlockSelector, CheckDeploymentResult,
    DeployAccountRequest, DeployAccountResult, DerivationRequest, GatewayError, GatewayErrorCode,
    OperationKind, OperationState,
};

impl<B, S, C> Gateway<B, S, C>
where
    B: GatewayBackend,
    S: SecretResolver,
    C: Clock,
{
    /// Derive a canonical account descriptor using the trusted secret boundary.
    pub async fn derive_account(
        &self,
        request: DerivationRequest,
    ) -> GatewayResult<GatewayResponse<AccountDescriptor>> {
        let queued = self.begin_operation(OperationKind::DeriveAccount).await?;
        self.set_operation(&queued.id, queued.kind, OperationState::Running, None)
            .await;

        match self.derive_account_descriptor(&request).await {
            Ok((_, account)) => {
                let status = self
                    .set_operation(
                        &queued.id,
                        queued.kind,
                        OperationState::Completed,
                        Some(account.provenance.clone()),
                    )
                    .await;
                Ok(GatewayResponse {
                    operation: status,
                    value: account,
                })
            }
            Err(error) => {
                self.reject_operation(&queued, error.clone(), None).await;
                Err(error)
            }
        }
    }

    /// Check deployment state for the canonical account derived from `request`.
    pub async fn check_deployment(
        &self,
        request: DerivationRequest,
    ) -> GatewayResult<GatewayResponse<CheckDeploymentResult>> {
        let queued = self.begin_operation(OperationKind::CheckDeployment).await?;
        self.set_operation(&queued.id, queued.kind, OperationState::Running, None)
            .await;

        match self.derive_account_descriptor(&request).await {
            Ok((_, account)) => match self
                .backend
                .check_deployed(&account.address, &BlockSelector::Latest)
                .await
            {
                Ok(true) => {
                    let result = CheckDeploymentResult {
                        account: account.clone(),
                        deployment: krusty_kms_domain::DeploymentState::Deployed,
                    };
                    let status = self
                        .set_operation(
                            &queued.id,
                            queued.kind,
                            OperationState::Completed,
                            Some(account.provenance.clone()),
                        )
                        .await;
                    Ok(GatewayResponse {
                        operation: status,
                        value: result,
                    })
                }
                Ok(false) => {
                    let result = CheckDeploymentResult {
                        account: account.clone(),
                        deployment: krusty_kms_domain::DeploymentState::Undeployed,
                    };
                    let status = self
                        .set_operation(
                            &queued.id,
                            queued.kind,
                            OperationState::Completed,
                            Some(account.provenance.clone()),
                        )
                        .await;
                    Ok(GatewayResponse {
                        operation: status,
                        value: result,
                    })
                }
                Err(error) => {
                    self.reject_operation(&queued, error.clone(), Some(account.provenance))
                        .await;
                    Err(error)
                }
            },
            Err(error) => {
                self.reject_operation(&queued, error.clone(), None).await;
                Err(error)
            }
        }
    }

    /// Deploy an OpenZeppelin account using the same canonical descriptor as derive/check.
    pub async fn deploy_account(
        &self,
        request: DeployAccountRequest,
    ) -> GatewayResult<GatewayResponse<DeployAccountResult>> {
        let queued = self.begin_operation(OperationKind::DeployAccount).await?;
        self.set_operation(&queued.id, queued.kind, OperationState::Running, None)
            .await;

        if let Err(error) = self.validate_wait_mode(request.mode) {
            self.reject_operation(&queued, error.clone(), None).await;
            return Err(error);
        }

        match self.derive_account_descriptor(&request.derivation).await {
            Ok((private_key, account)) => {
                if !matches!(
                    request.derivation.account_class.kind,
                    AccountClassKind::OpenZeppelin
                ) {
                    let error = GatewayError::new(
                        GatewayErrorCode::UnsupportedAccountClass,
                        false,
                        Some(
                            "deploy_account currently supports OpenZeppelin accounts only"
                                .to_string(),
                        ),
                    );
                    self.reject_operation(&queued, error.clone(), Some(account.provenance))
                        .await;
                    return Err(error);
                }

                match self
                    .backend
                    .deploy_open_zeppelin(&private_key, &account, request.mode)
                    .await
                {
                    Ok(DeployExecution::AlreadyDeployed) => {
                        let result = DeployAccountResult {
                            account: account.clone(),
                            deployment: krusty_kms_domain::DeploymentState::Deployed,
                            already_deployed: true,
                        };
                        let status = self
                            .set_operation(
                                &queued.id,
                                queued.kind,
                                OperationState::Completed,
                                Some(account.provenance.clone()),
                            )
                            .await;
                        Ok(GatewayResponse {
                            operation: status,
                            value: result,
                        })
                    }
                    Ok(DeployExecution::Submitted { tx_hash }) => {
                        let result = DeployAccountResult {
                            account: account.clone(),
                            deployment: krusty_kms_domain::DeploymentState::Deploying {
                                tx_hash: tx_hash.clone(),
                            },
                            already_deployed: false,
                        };
                        let status = self
                            .set_operation(
                                &queued.id,
                                queued.kind,
                                OperationState::Submitted {
                                    tx_hash: tx_hash.clone(),
                                },
                                Some(account.provenance.clone()),
                            )
                            .await;
                        Ok(GatewayResponse {
                            operation: status,
                            value: result,
                        })
                    }
                    Ok(DeployExecution::Accepted { tx_hash }) => {
                        let result = DeployAccountResult {
                            account: account.clone(),
                            deployment: krusty_kms_domain::DeploymentState::Deployed,
                            already_deployed: false,
                        };
                        let status = self
                            .set_operation(
                                &queued.id,
                                queued.kind,
                                OperationState::Accepted { tx_hash },
                                Some(account.provenance.clone()),
                            )
                            .await;
                        Ok(GatewayResponse {
                            operation: status,
                            value: result,
                        })
                    }
                    Err(error) => {
                        self.reject_operation(&queued, error.clone(), Some(account.provenance))
                            .await;
                        Err(error)
                    }
                }
            }
            Err(error) => {
                self.reject_operation(&queued, error.clone(), None).await;
                Err(error)
            }
        }
    }
}
