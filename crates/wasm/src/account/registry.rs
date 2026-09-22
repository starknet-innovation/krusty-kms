//! Known account classes by role, and derivability of a concrete deployment.

use super::helpers::parse_felt;
use krusty_kms::{inspect_deployment, known_account_classes, Derivability, NotDerivableReason};
use starknet_types_core::felt::Felt;
use wasm_bindgen::prelude::*;

/// Every account class this crate knows, labelled by the role it plays.
///
/// A class hash plays one of two roles, and a wallet needs both lists:
///
/// - `deployment`: the class an account is deployed with. It fixes the
///   address, so it is the class to **derive from** when looking for an
///   account from a seed.
/// - `implementation`: the class an account's address reports on chain
///   (`starknet_getClassHashAt`) and what to **accept when signing**; it
///   never fixes an address.
/// - `proxy_target`: the class a proxy delegates to, named in the proxy's
///   constructor calldata. It is code the account runs, but no address ever
///   reports it, so a signing allowlist must not expect it. These are the
///   values the Argent Cairo 0 proxy's `implementation` input takes.
///
/// Braavos accounts are deployed with a base class and upgraded to an
/// implementation class in the same transaction, so every Braavos account
/// runs a different class than it was deployed with. Argent and OpenZeppelin
/// classes play both roles, including the Argent Cairo 0 proxy: an unupgraded
/// Cairo 0 account reports the proxy's class hash, not its target's.
///
/// # Returns
/// JSON string: array of objects with fields:
/// - `family`: "open_zeppelin" | "argent" | "braavos"
/// - `classHash`: hex string
/// - `version`: vendor release label (e.g. "1.2.0", "0.4.0", "proxy")
/// - `label`: human-readable name
/// - `roles`: array of "deployment" | "implementation" | "proxy_target"
/// - `constructor`: the class's calldata convention, or `null` for a class
///   that is never deployed with. An object with `shape` ("public_key" |
///   "argent_owner_guardian_felts" | "argent_signer_with_optional_guardian" |
///   "argent_cairo0_proxy"), `fromSeed` (the calldata a seed reproduces, e.g.
///   `"[0, owner, 1]"`), `withGuardian` (the calldata once a guardian is set,
///   e.g. `"[0, owner, 0, 0, guardian]"`, or `null`) and `inputsOutsideSeed`
///   (constructor inputs a phrase cannot supply, e.g. `["guardian"]`). The
///   convention varies by version and by guardian presence and cannot be
///   inferred from the class hash, which is why it travels with the class.
///   An `implementation` placeholder takes its values from this registry's
///   `proxy_target` entries for the same family, so a template can be
///   rendered from the registry alone.
/// - `source`: URL of the public listing the entry was checked against
///
/// # Example (JavaScript)
/// ```javascript
/// const registry = JSON.parse(getAccountClassRegistry());
/// const deriveFrom = registry.filter(c => c.family === "braavos" && c.roles.includes("deployment"));
/// const acceptWhenSigning = registry.filter(c => c.family === "braavos" && c.roles.includes("implementation"));
/// // Values the Argent Cairo 0 proxy's `implementation` input takes:
/// const proxyTargets = registry.filter(c => c.family === "argent" && c.roles.includes("proxy_target"));
/// ```
#[wasm_bindgen(js_name = "getAccountClassRegistry")]
pub fn get_account_class_registry() -> Result<String, JsValue> {
    serde_json::to_string(&known_account_classes())
        .map_err(|e| JsValue::from_str(&format!("Serialization failed: {e}")))
}

/// State whether an account deployment can be found from a seed phrase.
///
/// Takes the three `DEPLOY_ACCOUNT` fields that fix an address. An account
/// that exists but whose address depends on inputs outside the seed (an
/// Argent guardian, a non-Starknet owner, a server-assigned salt) is
/// reported as `not_from_seed` with the reason, so a recovery flow can tell
/// "not discoverable from a phrase" apart from "no such account". Such an
/// account is still verifiable: check that `address` is the account's and
/// that `ownerPublicKey` is one of the seed's derived keys. `guardianPublicKey`
/// is the deploy-time guardian, which is the one that fixes the address; an
/// account's current guardian can have changed since.
///
/// Pass the class hash from the deploy transaction, not the class the account
/// runs today: for an upgraded account the current class is an implementation
/// class and the answer is `not_from_seed` / `implementation_class`.
///
/// # Arguments
/// * `class_hash` - `DEPLOY_ACCOUNT.class_hash` (hex string)
/// * `salt` - `DEPLOY_ACCOUNT.contract_address_salt` (hex string)
/// * `constructor_calldata` - `DEPLOY_ACCOUNT.constructor_calldata` (hex strings)
///
/// # Returns
/// JSON string with fields:
/// - `address`: the address these fields fix (deployer zero). Compare it with
///   the account being checked before trusting anything else in the result:
///   the fields are usually an RPC response, and fields that do not hash to
///   the account say nothing about it
/// - `known`: whether the class hash is in the registry
/// - `class`: the registry entry (see `getAccountClassRegistry`), or `null`
/// - `ownerPublicKey`: the Stark key the constructor binds as owner, or `null`
/// - `guardianPublicKey`: the guardian's Stark key when a Starknet-key
///   guardian is set, or `null`
/// - `derivability`: "from_seed" | "not_from_seed" | "unknown_class"
/// - `reason`: for `not_from_seed`, one of "guardian" | "non_starknet_owner" |
///   "salt_not_public_key" | "implementation_class" | "proxy_target_class" |
///   "unknown_proxy_implementation" | "unexpected_constructor_calldata";
///   otherwise `null`
#[wasm_bindgen(js_name = "inspectAccountDeployment")]
pub fn inspect_account_deployment(
    class_hash: &str,
    salt: &str,
    constructor_calldata: Vec<String>,
) -> Result<String, JsValue> {
    let class_hash = parse_felt(class_hash)?;
    let salt = parse_felt(salt)?;
    let calldata: Vec<Felt> = constructor_calldata
        .iter()
        .map(|s| parse_felt(s))
        .collect::<Result<Vec<_>, _>>()?;

    let inspection = inspect_deployment(&class_hash, &salt, &calldata);
    let (derivability, reason) = match inspection.derivability {
        Derivability::FromSeed => ("from_seed", None),
        Derivability::NotFromSeed(reason) => ("not_from_seed", Some(reason_label(reason))),
        Derivability::UnknownClass => ("unknown_class", None),
    };
    let json = serde_json::json!({
        "address": format!("{:#x}", inspection.address),
        "known": inspection.class.is_some(),
        "class": inspection.class,
        "ownerPublicKey": inspection.owner_public_key.map(|key| format!("{key:#x}")),
        "guardianPublicKey": inspection.guardian_public_key.map(|key| format!("{key:#x}")),
        "derivability": derivability,
        "reason": reason,
    });
    Ok(json.to_string())
}

fn reason_label(reason: NotDerivableReason) -> &'static str {
    match reason {
        NotDerivableReason::Guardian => "guardian",
        NotDerivableReason::NonStarknetOwner => "non_starknet_owner",
        NotDerivableReason::SaltNotPublicKey => "salt_not_public_key",
        NotDerivableReason::ImplementationClass => "implementation_class",
        NotDerivableReason::ProxyTargetClass => "proxy_target_class",
        NotDerivableReason::UnknownProxyImplementation => "unknown_proxy_implementation",
        NotDerivableReason::UnexpectedConstructorCalldata => "unexpected_constructor_calldata",
    }
}
