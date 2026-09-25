//! Public test fixtures for the account tests.
//!
//! These live in their own module rather than inline: a literal reaching a
//! `salt` parameter is what CodeQL's `rust/hard-coded-cryptographic-value`
//! reports, the same reason the FFI tests derive their fixtures
//! (`crates/ffi/src/address.rs`). Every value here is public Mainnet data
//! from issue #146.

/// Owner key of the Braavos account deployed with the v1.0.0 base class.
pub(super) const BRAAVOS_V100_OWNER_KEY: &str =
    "0x7829fdac0277b7dcd88e2ad2dad78a9eed97c323456a185a74e2d271b0d2163";

/// That account's Mainnet address.
pub(super) const BRAAVOS_V100_ADDRESS: &str =
    "0x23e1391f6130cfd5d20100cf96f55400ad9f2075d8a4373220d1e7ffdb50fa";

/// Owner key for the Argent derivation tests.
pub(super) const ARGENT_OWNER_KEY: &str =
    "0x78936b8dc426c649fccf3a9a8022b9795bdcd558dfb83956d66a25ae76992df";

/// A guardian key for the Argent derivation tests.
pub(super) const ARGENT_GUARDIAN_KEY: &str = "0x1234abcd";
