//! Entrypoint selectors from names. Keyless.

use starknet_rust_core::utils::starknet_keccak;
use starknet_types_core::felt::Felt;

/// Entrypoint selector for `name`: `starknet_keccak` of its UTF-8 bytes, i.e.
/// Keccak-256 with the top 6 bits cleared.
///
/// This is the plain hash, as starknet.js `getSelectorFromName` computes it
/// (pinned by `tests/fixtures/selector_vectors.json`, which CI re-verifies
/// with starknet.js), so a co-signer recomputes the selector a starknet.js
/// proposer used. It deliberately differs from cairo-lang and starknet-rs
/// `get_selector_from_name`, which map the Cairo 0 default entrypoints
/// `__default__` and `__l1_default__` to `0` and reject non-ASCII names.
pub fn selector_from_name(name: &str) -> Felt {
    starknet_keccak(name.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use starknet_rust_core::utils::get_selector_from_name;

    #[test]
    fn selector_from_name_matches_known_selectors() {
        // Well-known values: `transfer` (ERC-20) and `__execute__` (accounts).
        assert_eq!(
            selector_from_name("transfer"),
            Felt::from_hex_unchecked(
                "0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e"
            )
        );
        assert_eq!(
            selector_from_name("__execute__"),
            Felt::from_hex_unchecked(
                "0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"
            )
        );
    }

    #[test]
    fn selector_from_name_is_the_plain_hash_for_every_name() {
        // Agrees with the reference rule for ordinary names...
        for name in ["transfer", "__execute__", "__validate__", "initialize"] {
            assert_eq!(
                selector_from_name(name),
                get_selector_from_name(name).unwrap()
            );
        }
        // ...and, unlike it, has no special cases.
        for name in ["__default__", "__l1_default__", "tränsfer", ""] {
            assert_eq!(selector_from_name(name), starknet_keccak(name.as_bytes()));
        }
        assert_ne!(selector_from_name("__default__"), Felt::ZERO);
        assert_ne!(selector_from_name("__l1_default__"), Felt::ZERO);
    }
}
