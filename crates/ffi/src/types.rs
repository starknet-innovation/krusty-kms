//! `#[repr(C)]` types matching `kms.h`.

/// A 32-byte Stark field element (big-endian).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KmsFelt {
    pub bytes: [u8; 32],
}

/// A projective curve point (x, y, z) in big-endian felt representation.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KmsProjectivePoint {
    pub x: KmsFelt,
    pub y: KmsFelt,
    pub z: KmsFelt,
}

/// An affine curve point (x, y) in big-endian felt representation.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KmsAffinePoint {
    pub x: KmsFelt,
    pub y: KmsFelt,
}

/// A Tongo key pair (private key + public key).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KmsTongoKeyPair {
    pub private_key: KmsFelt,
    pub public_key: KmsProjectivePoint,
}

/// A Nostr key pair (32-byte secret + 32-byte x-only pubkey).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KmsNostrKeyPair {
    pub private_key: [u8; 32],
    pub public_key_xonly: [u8; 32],
}

/// Opaque handle to a `TongoAccount` stored in the global registry.
pub type KmsAccountHandle = u64;

/// Account state exposed over the C ABI.
///
/// Balances are split into `(low, high)` u64 pairs because C has no portable
/// u128 type.  `value = low + high * 2^64`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KmsAccountState {
    pub balance_low: u64,
    pub balance_high: u64,
    pub pending_balance_low: u64,
    pub pending_balance_high: u64,
    pub nonce: u64,
}

/// Secp256k1 (Ethereum) ECDSA signature in the 5-felt OZ format.
///
/// `[r_low, r_high, s_low, s_high, v]`
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KmsEthSignature {
    pub r_low: KmsFelt,
    pub r_high: KmsFelt,
    pub s_low: KmsFelt,
    pub s_high: KmsFelt,
    pub v: KmsFelt,
}
