//! Signing flows for Stark and Nostr domains.

use crate::backend::GatewayBackend;
use crate::clock::Clock;
use crate::errors::{map_domain_error, map_kms_error};
use crate::gateway::Gateway;
use crate::types::{GatewayResponse, GatewayResult, SecretResolver};
use krusty_kms::{sign_nostr_event_id, sign_nostr_message, sign_stark_hash};
use krusty_kms_domain::{
    FeltHex, HexBytes, OperationKind, OperationState, Provenance, RawMessagePayload, SignRequest,
    SignResult,
};

impl<B, S, C> Gateway<B, S, C>
where
    B: GatewayBackend,
    S: SecretResolver,
    C: Clock,
{
    /// Sign a typed payload using the explicit domain-separated secret boundary.
    pub async fn sign(&self, request: SignRequest) -> GatewayResult<GatewayResponse<SignResult>> {
        let queued = self.begin_operation(OperationKind::Sign).await?;
        self.set_operation(&queued.id, queued.kind, OperationState::Running, None)
            .await;

        if let Err(error) = request.validate().map_err(map_domain_error) {
            self.reject_operation(&queued, error.clone(), None).await;
            return Err(error);
        }

        let provenance = sign_provenance(&request);

        match &request {
            SignRequest::StarkHash {
                secret,
                key_domain,
                derivation_path,
                hash,
                ..
            }
            | SignRequest::StarkRawMessage {
                secret,
                key_domain,
                derivation_path,
                message: hash,
                ..
            } => {
                let private_key = match self
                    .secret_resolver
                    .resolve_private_key(secret, key_domain.key_domain(), *derivation_path)
                    .await
                {
                    Ok(key) => key,
                    Err(error) => {
                        self.reject_operation(&queued, error.clone(), None).await;
                        return Err(error);
                    }
                };

                match sign_stark_hash(private_key.expose_secret(), &hash.to_felt()) {
                    Ok(signed) => {
                        let status = self
                            .set_operation(
                                &queued.id,
                                queued.kind,
                                OperationState::Completed,
                                provenance.clone(),
                            )
                            .await;
                        Ok(GatewayResponse {
                            operation: status,
                            value: SignResult::StarkEcdsa {
                                public_key: FeltHex::from_felt(signed.public_key),
                                signature_r: FeltHex::from_felt(signed.r),
                                signature_s: FeltHex::from_felt(signed.s),
                            },
                        })
                    }
                    Err(error) => {
                        let gateway_error = map_kms_error(error);
                        self.reject_operation(&queued, gateway_error.clone(), provenance)
                            .await;
                        Err(gateway_error)
                    }
                }
            }
            SignRequest::NostrEvent {
                secret,
                derivation_path,
                event_id,
            } => {
                let private_key = match self
                    .secret_resolver
                    .resolve_nostr_private_key(secret, *derivation_path)
                    .await
                {
                    Ok(key) => key,
                    Err(error) => {
                        self.reject_operation(&queued, error.clone(), None).await;
                        return Err(error);
                    }
                };

                let event_id = match event_id.to_array::<32>() {
                    Ok(value) => value,
                    Err(error) => {
                        let gateway_error = map_domain_error(error);
                        self.reject_operation(&queued, gateway_error.clone(), None)
                            .await;
                        return Err(gateway_error);
                    }
                };

                match sign_nostr_event_id(&private_key, &event_id) {
                    Ok(signed) => {
                        let status = self
                            .set_operation(&queued.id, queued.kind, OperationState::Completed, None)
                            .await;
                        Ok(GatewayResponse {
                            operation: status,
                            value: SignResult::NostrBip340 {
                                public_key: HexBytes::from_bytes(&signed.public_key),
                                signature: HexBytes::from_bytes(&signed.signature),
                            },
                        })
                    }
                    Err(error) => {
                        let gateway_error = map_kms_error(error);
                        self.reject_operation(&queued, gateway_error.clone(), None)
                            .await;
                        Err(gateway_error)
                    }
                }
            }
            SignRequest::NostrRawMessage {
                secret,
                derivation_path,
                payload,
            } => {
                let private_key = match self
                    .secret_resolver
                    .resolve_nostr_private_key(secret, *derivation_path)
                    .await
                {
                    Ok(key) => key,
                    Err(error) => {
                        self.reject_operation(&queued, error.clone(), None).await;
                        return Err(error);
                    }
                };

                let message = match payload {
                    RawMessagePayload::Utf8(value) => value.as_bytes().to_vec(),
                    RawMessagePayload::Hex(bytes) => bytes.to_vec(),
                };

                match sign_nostr_message(&private_key, &message) {
                    Ok(signed) => {
                        let status = self
                            .set_operation(&queued.id, queued.kind, OperationState::Completed, None)
                            .await;
                        Ok(GatewayResponse {
                            operation: status,
                            value: SignResult::NostrBip340 {
                                public_key: HexBytes::from_bytes(&signed.public_key),
                                signature: HexBytes::from_bytes(&signed.signature),
                            },
                        })
                    }
                    Err(error) => {
                        let gateway_error = map_kms_error(error);
                        self.reject_operation(&queued, gateway_error.clone(), None)
                            .await;
                        Err(gateway_error)
                    }
                }
            }
        }
    }
}

/// Provenance attached to sign operations that carry a chain id.
fn sign_provenance(request: &SignRequest) -> Option<Provenance> {
    request.chain_id().map(|chain_id| Provenance {
        chain_id,
        key_domain: request.key_domain(),
        derivation_path: request.derivation_path(),
        class_hash: None,
    })
}
