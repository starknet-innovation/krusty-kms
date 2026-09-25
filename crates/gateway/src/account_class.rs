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
                    ArgentAccount::try_with_class_hash(class_hash.to_felt())
                        .map_err(map_kms_error)?
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
                Some(class_hash) => resolve_braavos_class(
                    class_hash.to_felt(),
                    chain_id,
                    spec.allow_unlisted_class_hash,
                )?,
                None => BraavosAccount::new(),
            }))
        }
    }
}

/// Braavos addresses are fixed by a base (deployment) class. The allowlist
/// holds exactly those; the override waives it for a class this crate does
/// not know, but cannot make a known implementation class fix an address, so
/// that stays rejected.
fn resolve_braavos_class(
    class_hash: Felt,
    chain_id: ChainId,
    allow_unlisted: bool,
) -> GatewayResult<BraavosAccount> {
    enforce_class_hash_allowlist(
        class_hash,
        AccountClassKind::Braavos,
        chain_id,
        allow_unlisted,
    )?;
    match BraavosAccount::try_with_class_hash(class_hash) {
        Ok(account) => Ok(account),
        Err(_) if allow_unlisted && !BraavosAccount::is_implementation_class_hash(&class_hash) => {
            Ok(BraavosAccount::with_class_hash(class_hash))
        }
        Err(err) => Err(map_kms_error(err)),
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
        // Deployment (base) classes only: a Braavos implementation class fixes
        // no address, so deriving or deploying with it is always wrong.
        AccountClassKind::Braavos => BraavosAccount::deployment_class_hashes(),
    }
}

pub(crate) fn enforce_class_hash_allowlist(
    class_hash: Felt,
    kind: AccountClassKind,
    chain_id: ChainId,
    allow_unlisted: bool,
) -> GatewayResult<()> {
    // A Braavos implementation class is not "unlisted": it is known, and known
    // never to fix an address. It is refused before the override so the check
    // holds for every caller; no override helps, so say what does.
    if kind == AccountClassKind::Braavos
        && BraavosAccount::is_implementation_class_hash(&class_hash)
    {
        return Err(GatewayError::new(
            GatewayErrorCode::InvalidClassHash,
            false,
            Some(format!(
                "class_hash {class_hash:#x} is a Braavos account implementation class; \
                 addresses are fixed by a base (deployment) class, use one of those"
            )),
        ));
    }

    if allow_unlisted {
        return Ok(());
    }

    let allowed = known_class_hashes(kind, chain_id);
    if allowed.contains(&class_hash) {
        return Ok(());
    }

    // Argent resolution needs a known constructor layout, so the override
    // cannot unblock an unlisted Argent class; do not advertise it there.
    let override_hint = match kind {
        AccountClassKind::Argent => "",
        _ => "; set allow_unlisted_class_hash=true to override",
    };
    Err(GatewayError::new(
        GatewayErrorCode::InvalidClassHash,
        false,
        Some(format!(
            "class_hash {class_hash:#x} is not on the known {kind:?} allowlist{override_hint}"
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
