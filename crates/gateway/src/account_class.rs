//! Account class resolution and the known class-hash allowlist.

use crate::errors::map_kms_error;
use crate::types::GatewayResult;
use krusty_kms::{AccountClass, ArgentAccount, BraavosAccount, OpenZeppelinAccount, SaltPolicy};
use krusty_kms_common::{ChainId, KmsError};
use krusty_kms_domain::{
    AccountClassKind, AccountClassSpec, GatewayError, GatewayErrorCode, SaltPolicySpec,
};
use starknet_types_core::felt::Felt;

pub(crate) fn resolve_account_class(
    spec: &AccountClassSpec,
    chain_id: ChainId,
) -> GatewayResult<ResolvedAccountClass> {
    match spec.kind {
        AccountClassKind::OpenZeppelin => {
            let account = match (&spec.class_hash, &spec.source_label) {
                (Some(class_hash), _) => {
                    enforce_class_hash_allowlist(
                        class_hash.to_felt(),
                        AccountClassKind::OpenZeppelin,
                        chain_id,
                        spec.allow_unlisted_class_hash,
                    )?;
                    OpenZeppelinAccount::from_class_hash(class_hash.to_felt())
                }
                (None, Some(version)) => {
                    OpenZeppelinAccount::from_manifest(chain_id, version).map_err(map_kms_error)?
                }
                (None, None) => OpenZeppelinAccount::latest(chain_id).map_err(map_kms_error)?,
            };
            Ok(ResolvedAccountClass::OpenZeppelin(account))
        }
        AccountClassKind::Argent => {
            if spec.source_label.is_some() {
                return Err(GatewayError::new(
                    GatewayErrorCode::UnsupportedAccountClass,
                    false,
                    Some("Argent account resolution does not support source_label".to_string()),
                ));
            }

            Ok(ResolvedAccountClass::Argent(match &spec.class_hash {
                Some(class_hash) => {
                    enforce_class_hash_allowlist(
                        class_hash.to_felt(),
                        AccountClassKind::Argent,
                        chain_id,
                        spec.allow_unlisted_class_hash,
                    )?;
                    ArgentAccount::with_class_hash(class_hash.to_felt())
                }
                None => ArgentAccount::new(),
            }))
        }
        AccountClassKind::Braavos => {
            if spec.source_label.is_some() {
                return Err(GatewayError::new(
                    GatewayErrorCode::UnsupportedAccountClass,
                    false,
                    Some("Braavos account resolution does not support source_label".to_string()),
                ));
            }

            Ok(ResolvedAccountClass::Braavos(match &spec.class_hash {
                Some(class_hash) => {
                    enforce_class_hash_allowlist(
                        class_hash.to_felt(),
                        AccountClassKind::Braavos,
                        chain_id,
                        spec.allow_unlisted_class_hash,
                    )?;
                    BraavosAccount::with_class_hash(class_hash.to_felt())
                }
                None => BraavosAccount::new(),
            }))
        }
    }
}

fn known_class_hashes(kind: AccountClassKind, chain_id: ChainId) -> Vec<Felt> {
    match kind {
        AccountClassKind::OpenZeppelin => {
            let mut hashes = Vec::new();
            if let Ok(latest) = OpenZeppelinAccount::latest(chain_id) {
                hashes.push(latest.class_hash());
            }
            // Also accept the same class hash from the peer network when present.
            for peer in [ChainId::Sepolia, ChainId::Mainnet] {
                if peer == chain_id {
                    continue;
                }
                if let Ok(account) = OpenZeppelinAccount::latest(peer) {
                    let hash = account.class_hash();
                    if !hashes.contains(&hash) {
                        hashes.push(hash);
                    }
                }
            }
            hashes
        }
        AccountClassKind::Argent => ArgentAccount::known_class_hashes(),
        AccountClassKind::Braavos => {
            let mut hashes = vec![Felt::from_hex(BraavosAccount::CLASS_HASH).unwrap()];
            if let Ok(legacy) = Felt::from_hex(BraavosAccount::LEGACY_CLASS_HASH) {
                hashes.push(legacy);
            }
            hashes
        }
    }
}

pub(crate) fn enforce_class_hash_allowlist(
    class_hash: Felt,
    kind: AccountClassKind,
    chain_id: ChainId,
    allow_unlisted: bool,
) -> GatewayResult<()> {
    if allow_unlisted {
        return Ok(());
    }

    let allowed = known_class_hashes(kind, chain_id);
    if allowed.contains(&class_hash) {
        return Ok(());
    }

    Err(GatewayError::new(
        GatewayErrorCode::InvalidClassHash,
        false,
        Some(format!(
            "class_hash {class_hash:#x} is not on the known {:?} allowlist; set allow_unlisted_class_hash=true to override",
            kind
        )),
    ))
}

pub(crate) fn to_salt_policy(spec: &SaltPolicySpec) -> SaltPolicy {
    match spec {
        SaltPolicySpec::PublicKey => SaltPolicy::PublicKey,
        SaltPolicySpec::Zero => SaltPolicy::Zero,
        SaltPolicySpec::Explicit(salt) => SaltPolicy::Explicit(salt.to_felt()),
    }
}

pub(crate) enum ResolvedAccountClass {
    OpenZeppelin(OpenZeppelinAccount),
    Argent(ArgentAccount),
    Braavos(BraavosAccount),
}

impl ResolvedAccountClass {
    fn as_account_class(&self) -> &dyn AccountClass {
        match self {
            Self::OpenZeppelin(account) => account,
            Self::Argent(account) => account,
            Self::Braavos(account) => account,
        }
    }

    pub(crate) fn class_hash(&self) -> Felt {
        self.as_account_class().class_hash()
    }

    pub(crate) fn build_constructor_calldata(&self, public_key: &Felt) -> Vec<Felt> {
        self.as_account_class()
            .build_constructor_calldata(public_key)
    }

    pub(crate) fn calculate_address(
        &self,
        public_key: &Felt,
        salt_policy: SaltPolicy,
    ) -> Result<Felt, KmsError> {
        self.as_account_class()
            .calculate_address(public_key, salt_policy)
    }
}
