//! The constructor calldata convention of a deployment class.
//!
//! The convention varies by class version *and* by whether a guardian is
//! set, and neither is inferable from the class hash, so the registry
//! publishes it next to every class.

use super::ArgentConstructorLayout;
use serde::{Serialize, Serializer};

/// Constructor calldata convention of a deployment class.
///
/// The convention varies by class version *and* by whether a guardian is
/// set, and neither is inferable from the class hash, so it is published next
/// to every class. [`Self::seed_calldata`] is the shape a seed reproduces on
/// its own; [`Self::guardian_calldata`] is the shape once a guardian is known.
/// Serialises as an object: `{ shape, fromSeed, withGuardian, inputsOutsideSeed }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstructorShape {
    /// `[public_key]`: OpenZeppelin `AccountUpgradeable` and the Braavos base account.
    PublicKey,
    /// `[owner, guardian]` as felts: Argent v0.3.0 and v0.3.1.
    ArgentOwnerGuardianFelts,
    /// `[0, owner, 1]` (`Signer::Starknet`, `Option::None`): Argent v0.4.0 and later.
    ArgentSignerWithOptionalGuardian,
    /// `[implementation, selector("initialize"), 2, owner, guardian]`: the Argent Cairo 0 proxy.
    ArgentCairo0Proxy,
}

impl ConstructorShape {
    /// Stable snake_case identifier of the shape.
    pub fn name(self) -> &'static str {
        match self {
            Self::PublicKey => "public_key",
            Self::ArgentOwnerGuardianFelts => "argent_owner_guardian_felts",
            Self::ArgentSignerWithOptionalGuardian => "argent_signer_with_optional_guardian",
            Self::ArgentCairo0Proxy => "argent_cairo0_proxy",
        }
    }

    /// Calldata for a seed-derived owner and no guardian, as a template. This
    /// is the shape [`crate::generate_candidates`] derives from.
    pub fn seed_calldata(self) -> &'static str {
        match self {
            Self::PublicKey => "[public_key]",
            Self::ArgentOwnerGuardianFelts => "[owner, 0]",
            Self::ArgentSignerWithOptionalGuardian => "[0, owner, 1]",
            Self::ArgentCairo0Proxy => "[implementation, selector(\"initialize\"), 2, owner, 0]",
        }
    }

    /// Calldata once a Starknet-key guardian is set, as a template, for the
    /// shapes that take one. Discovery cannot enumerate these; they verify an
    /// account whose address and guardian are known.
    pub fn guardian_calldata(self) -> Option<&'static str> {
        match self {
            Self::PublicKey => None,
            Self::ArgentOwnerGuardianFelts => Some("[owner, guardian]"),
            Self::ArgentSignerWithOptionalGuardian => Some("[0, owner, 0, 0, guardian]"),
            Self::ArgentCairo0Proxy => {
                Some("[implementation, selector(\"initialize\"), 2, owner, guardian]")
            }
        }
    }

    /// Constructor inputs that are not a function of the seed. A deployment
    /// that set any of them has an address a phrase alone cannot find; route
    /// it to an address lookup instead of reporting it missing.
    pub fn inputs_outside_seed(self) -> &'static [&'static str] {
        match self {
            Self::PublicKey => &[],
            Self::ArgentOwnerGuardianFelts
            | Self::ArgentSignerWithOptionalGuardian
            | Self::ArgentCairo0Proxy => &["guardian"],
        }
    }

    /// The Argent Cairo 1 layout this shape corresponds to, if any.
    pub fn argent_layout(self) -> Option<ArgentConstructorLayout> {
        match self {
            Self::ArgentOwnerGuardianFelts => Some(ArgentConstructorLayout::OwnerGuardianFelts),
            Self::ArgentSignerWithOptionalGuardian => {
                Some(ArgentConstructorLayout::SignerWithOptionalGuardian)
            }
            Self::PublicKey | Self::ArgentCairo0Proxy => None,
        }
    }
}

impl Serialize for ConstructorShape {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("ConstructorShape", 4)?;
        state.serialize_field("shape", self.name())?;
        state.serialize_field("fromSeed", self.seed_calldata())?;
        state.serialize_field("withGuardian", &self.guardian_calldata())?;
        state.serialize_field("inputsOutsideSeed", self.inputs_outside_seed())?;
        state.end()
    }
}

impl From<ArgentConstructorLayout> for ConstructorShape {
    fn from(layout: ArgentConstructorLayout) -> Self {
        match layout {
            ArgentConstructorLayout::OwnerGuardianFelts => Self::ArgentOwnerGuardianFelts,
            ArgentConstructorLayout::SignerWithOptionalGuardian => {
                Self::ArgentSignerWithOptionalGuardian
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account_class::ArgentCairo0;
    use starknet_types_core::felt::Felt;

    /// Render a published template into felts, token by token. Any token the
    /// renderer does not know fails the test, so a template cannot drift into
    /// a shape the builders do not produce.
    fn render(template: &str, owner: Felt, guardian: Felt, implementation: Felt) -> Vec<Felt> {
        let inner = template
            .strip_prefix('[')
            .and_then(|t| t.strip_suffix(']'))
            .unwrap_or_else(|| panic!("template is not bracketed: {template}"));
        inner
            .split(", ")
            .map(|token| match token {
                "public_key" | "owner" => owner,
                "guardian" => guardian,
                "implementation" => implementation,
                "selector(\"initialize\")" => ArgentCairo0::initialize_selector(),
                number => Felt::from(
                    number
                        .parse::<u64>()
                        .unwrap_or_else(|_| panic!("unknown template token {number:?}")),
                ),
            })
            .collect()
    }

    /// Every published template renders to exactly what the matching builder
    /// emits, element for element.
    #[test]
    fn calldata_templates_match_the_builders() {
        let pk = Felt::from(42u64);
        let guardian = Felt::from(7u64);
        let implementation = Felt::from(3u64);
        for shape in [
            ConstructorShape::ArgentOwnerGuardianFelts,
            ConstructorShape::ArgentSignerWithOptionalGuardian,
        ] {
            let layout = shape.argent_layout().unwrap();
            assert_eq!(
                render(shape.seed_calldata(), pk, guardian, implementation),
                layout.constructor_calldata(&pk),
                "{shape:?} seed template"
            );
            assert_eq!(
                render(
                    shape.guardian_calldata().unwrap(),
                    pk,
                    guardian,
                    implementation
                ),
                layout.constructor_calldata_with_guardian(&pk, &guardian),
                "{shape:?} guardian template"
            );
            assert_eq!(shape.inputs_outside_seed(), ["guardian"]);
        }

        let proxy = ConstructorShape::ArgentCairo0Proxy;
        assert_eq!(
            render(proxy.seed_calldata(), pk, guardian, implementation),
            ArgentCairo0::constructor_calldata(&implementation, &pk)
        );
        assert_eq!(
            render(
                proxy.guardian_calldata().unwrap(),
                pk,
                guardian,
                implementation
            ),
            ArgentCairo0::constructor_calldata_with_guardian(&implementation, &pk, &guardian)
        );
        assert_eq!(proxy.inputs_outside_seed(), ["guardian"]);

        let public_key = ConstructorShape::PublicKey;
        assert_eq!(
            render(public_key.seed_calldata(), pk, guardian, implementation),
            vec![pk]
        );
        assert_eq!(public_key.guardian_calldata(), None);
        assert!(public_key.inputs_outside_seed().is_empty());
    }

    #[test]
    #[should_panic(expected = "unknown template token")]
    fn render_rejects_unknown_tokens() {
        render("[owner, guardan]", Felt::ONE, Felt::TWO, Felt::THREE);
    }
}
