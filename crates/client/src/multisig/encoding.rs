//! Hex encodings and serde adapters shared by the multisig wire types.

#[cfg(feature = "nats")]
use krusty_kms_common::Address;
use starknet_types_core::felt::Felt;

pub(super) fn felt_to_hex(felt: Felt) -> String {
    format!("0x{:064x}", felt)
}

#[cfg(feature = "nats")]
pub(super) fn felt_subject_token(felt: Felt) -> String {
    felt_to_hex(felt).trim_start_matches("0x").to_string()
}

#[cfg(feature = "nats")]
pub(super) fn address_subject_token(address: Address) -> String {
    felt_subject_token(address.as_felt())
}

fn parse_felt_hex(value: &str) -> std::result::Result<Felt, String> {
    Felt::from_hex(value).map_err(|error| error.to_string())
}

pub(super) mod serde_felt_hex {
    use super::{felt_to_hex, parse_felt_hex};
    use serde::{Deserialize, Deserializer, Serializer};
    use starknet_types_core::felt::Felt;

    pub fn serialize<S>(felt: &Felt, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&felt_to_hex(*felt))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Felt, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        parse_felt_hex(&value).map_err(serde::de::Error::custom)
    }
}

pub(super) mod serde_felt_hex_vec {
    use super::{felt_to_hex, parse_felt_hex};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use starknet_types_core::felt::Felt;

    pub fn serialize<S>(felts: &[Felt], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = felts.iter().copied().map(felt_to_hex).collect::<Vec<_>>();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Vec<Felt>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<String>::deserialize(deserializer)?;
        values
            .iter()
            .map(|value| parse_felt_hex(value).map_err(serde::de::Error::custom))
            .collect()
    }
}

pub(super) mod serde_address_hex {
    use krusty_kms_common::Address;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(address: &Address, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&address.to_hex())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<Address, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Address::from_hex(&value).map_err(serde::de::Error::custom)
    }
}
