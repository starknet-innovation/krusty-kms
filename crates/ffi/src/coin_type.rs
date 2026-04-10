//! Coin type constant getters.

#[no_mangle]
pub extern "C" fn kms_get_coin_type_tongo() -> u32 {
    krusty_kms::TONGO_COIN_TYPE
}

#[no_mangle]
pub extern "C" fn kms_get_coin_type_starknet() -> u32 {
    krusty_kms::STARKNET_COIN_TYPE
}

#[no_mangle]
pub extern "C" fn kms_get_coin_type_nostr() -> u32 {
    krusty_kms::NOSTR_COIN_TYPE
}
