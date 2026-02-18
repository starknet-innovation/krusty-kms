use std::ffi::{c_char, CStr, CString};

#[derive(Debug)]
pub enum Error {
    Ffi { code: i32, message: String },
    Nul(std::ffi::NulError),
}

pub type Result<T> = std::result::Result<T, Error>;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Ffi { code, message } => write!(f, "kms ffi error {code}: {message}"),
            Error::Nul(_) => write!(f, "nul byte in input"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Ffi { .. } => None,
            Error::Nul(err) => Some(err),
        }
    }
}

impl From<std::ffi::NulError> for Error {
    fn from(value: std::ffi::NulError) -> Self {
        Error::Nul(value)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KmsFelt {
    pub bytes: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KmsProjectivePoint {
    pub x: KmsFelt,
    pub y: KmsFelt,
    pub z: KmsFelt,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KmsAffinePoint {
    pub x: KmsFelt,
    pub y: KmsFelt,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KmsTongoKeyPair {
    pub private_key: KmsFelt,
    pub public_key: KmsProjectivePoint,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KmsNostrKeyPair {
    pub private_key: [u8; 32],
    pub public_key_xonly: [u8; 32],
}

#[link(name = "kms")]
unsafe extern "C" {
    fn kms_get_abi_version(major: *mut u32, minor: *mut u32) -> i32;
    fn kms_get_version_string(out: *mut c_char, out_len: usize, out_written: *mut usize) -> i32;

    fn kms_felt_from_hex(hex: *const c_char, out: *mut KmsFelt) -> i32;
    fn kms_felt_to_hex(value: *const KmsFelt, out: *mut c_char, out_len: usize, out_written: *mut usize) -> i32;
    fn kms_felt_from_bytes_be(bytes: *const u8, bytes_len: usize, out: *mut KmsFelt) -> i32;
    fn kms_felt_to_bytes_be(value: *const KmsFelt, out: *mut u8, out_len: usize, out_written: *mut usize) -> i32;

    fn kms_projective_from_affine(affine: *const KmsAffinePoint, out: *mut KmsProjectivePoint) -> i32;
    fn kms_projective_to_affine(point: *const KmsProjectivePoint, out: *mut KmsAffinePoint) -> i32;

    fn kms_pedersen_hash(left: *const KmsFelt, right: *const KmsFelt, out: *mut KmsFelt) -> i32;
    fn kms_poseidon_hash_many(values: *const KmsFelt, values_len: usize, out: *mut KmsFelt) -> i32;

    fn kms_generate_mnemonic(word_count: u32, out: *mut c_char, out_len: usize, out_written: *mut usize) -> i32;
    fn kms_generate_mnemonic_from_entropy(entropy: *const u8, entropy_len: usize, out: *mut c_char, out_len: usize, out_written: *mut usize) -> i32;
    fn kms_validate_mnemonic(phrase: *const c_char) -> i32;
    fn kms_mnemonic_to_seed(phrase: *const c_char, passphrase: *const c_char, out: *mut u8, out_len: usize, out_written: *mut usize) -> i32;

    fn kms_derive_private_key_with_coin_type(
        mnemonic: *const c_char,
        index: u32,
        account_index: u32,
        coin_type: u32,
        passphrase: *const c_char,
        out: *mut KmsFelt,
    ) -> i32;
    fn kms_derive_keypair_with_coin_type(
        mnemonic: *const c_char,
        index: u32,
        account_index: u32,
        coin_type: u32,
        passphrase: *const c_char,
        out: *mut KmsTongoKeyPair,
    ) -> i32;
    fn kms_derive_view_private_key(
        mnemonic: *const c_char,
        index: u32,
        account_index: u32,
        passphrase: *const c_char,
        out: *mut KmsFelt,
    ) -> i32;
    fn kms_derive_view_keypair(
        mnemonic: *const c_char,
        index: u32,
        account_index: u32,
        passphrase: *const c_char,
        out: *mut KmsTongoKeyPair,
    ) -> i32;
    fn kms_derive_nostr_private_key(
        mnemonic: *const c_char,
        index: u32,
        account_index: u32,
        passphrase: *const c_char,
        out: *mut u8,
    ) -> i32;
    fn kms_derive_nostr_keypair(
        mnemonic: *const c_char,
        index: u32,
        account_index: u32,
        passphrase: *const c_char,
        out: *mut KmsNostrKeyPair,
    ) -> i32;

    fn kms_calculate_contract_address(
        salt: *const KmsFelt,
        class_hash: *const KmsFelt,
        constructor_calldata: *const KmsFelt,
        constructor_calldata_len: usize,
        deployer_address: *const KmsFelt,
        out: *mut KmsFelt,
    ) -> i32;
    fn kms_derive_oz_account_address(
        public_key_x: *const KmsFelt,
        class_hash: *const KmsFelt,
        salt: *const KmsFelt,
        out: *mut KmsFelt,
    ) -> i32;

    fn kms_get_coin_type_tongo() -> u32;
    fn kms_get_coin_type_starknet() -> u32;
    fn kms_get_coin_type_tongo_view() -> u32;
    fn kms_get_coin_type_nostr() -> u32;

    fn kms_error_name(code: i32) -> *const c_char;
    fn kms_error_message(code: i32) -> *const c_char;
}

fn check(code: i32) -> Result<()> {
    if code == 0 {
        return Ok(());
    }

    let message = unsafe {
        let ptr = kms_error_message(code);
        if ptr.is_null() {
            "unknown ffi error".to_string()
        } else {
            CStr::from_ptr(ptr).to_string_lossy().to_string()
        }
    };

    Err(Error::Ffi { code, message })
}

fn dynamic_string<F>(mut call: F) -> Result<String>
where
    F: FnMut(*mut c_char, usize, *mut usize) -> i32,
{
    let mut written = 0usize;
    check(call(std::ptr::null_mut(), 0, &mut written))?;

    let mut out = vec![0u8; written.saturating_add(1)];
    check(call(out.as_mut_ptr().cast(), out.len(), &mut written))?;
    out.truncate(written);

    String::from_utf8(out).map_err(|e| Error::Ffi {
        code: -10,
        message: format!("invalid utf-8 from ffi: {e}"),
    })
}

pub fn abi_version() -> Result<(u32, u32)> {
    let mut major = 0u32;
    let mut minor = 0u32;
    check(unsafe { kms_get_abi_version(&mut major, &mut minor) })?;
    Ok((major, minor))
}

pub fn version_string() -> Result<String> {
    dynamic_string(|out, out_len, out_written| unsafe {
        kms_get_version_string(out, out_len, out_written)
    })
}

pub fn coin_types() -> (u32, u32, u32, u32) {
    unsafe {
        (
            kms_get_coin_type_tongo(),
            kms_get_coin_type_starknet(),
            kms_get_coin_type_tongo_view(),
            kms_get_coin_type_nostr(),
        )
    }
}

pub fn error_name(code: i32) -> String {
    unsafe {
        let ptr = kms_error_name(code);
        if ptr.is_null() {
            return "KMS_ERR_INTERNAL".to_string();
        }
        CStr::from_ptr(ptr).to_string_lossy().to_string()
    }
}

pub fn error_message(code: i32) -> String {
    unsafe {
        let ptr = kms_error_message(code);
        if ptr.is_null() {
            return "unknown error".to_string();
        }
        CStr::from_ptr(ptr).to_string_lossy().to_string()
    }
}

pub fn felt_from_hex(hex: &str) -> Result<KmsFelt> {
    let mut out = KmsFelt::default();
    let c_hex = CString::new(hex)?;
    check(unsafe { kms_felt_from_hex(c_hex.as_ptr(), &mut out) })?;
    Ok(out)
}

pub fn felt_to_hex(value: &KmsFelt) -> Result<String> {
    dynamic_string(|out, out_len, out_written| unsafe {
        kms_felt_to_hex(value, out, out_len, out_written)
    })
}

pub fn felt_from_bytes_be(bytes: &[u8]) -> Result<KmsFelt> {
    let mut out = KmsFelt::default();
    check(unsafe { kms_felt_from_bytes_be(bytes.as_ptr(), bytes.len(), &mut out) })?;
    Ok(out)
}

pub fn felt_to_bytes_be(value: &KmsFelt) -> Result<Vec<u8>> {
    let mut out = vec![0u8; 32];
    let mut written = 0usize;
    check(unsafe { kms_felt_to_bytes_be(value, out.as_mut_ptr(), out.len(), &mut written) })?;
    out.truncate(written);
    Ok(out)
}

pub fn projective_from_affine(affine: &KmsAffinePoint) -> Result<KmsProjectivePoint> {
    let mut out = KmsProjectivePoint::default();
    check(unsafe { kms_projective_from_affine(affine, &mut out) })?;
    Ok(out)
}

pub fn projective_to_affine(point: &KmsProjectivePoint) -> Result<KmsAffinePoint> {
    let mut out = KmsAffinePoint::default();
    check(unsafe { kms_projective_to_affine(point, &mut out) })?;
    Ok(out)
}

pub fn pedersen_hash(left: &KmsFelt, right: &KmsFelt) -> Result<KmsFelt> {
    let mut out = KmsFelt::default();
    check(unsafe { kms_pedersen_hash(left, right, &mut out) })?;
    Ok(out)
}

pub fn poseidon_hash_many(values: &[KmsFelt]) -> Result<KmsFelt> {
    let mut out = KmsFelt::default();
    check(unsafe { kms_poseidon_hash_many(values.as_ptr(), values.len(), &mut out) })?;
    Ok(out)
}

pub fn generate_mnemonic(word_count: u32) -> Result<String> {
    dynamic_string(|out, out_len, out_written| unsafe {
        kms_generate_mnemonic(word_count, out, out_len, out_written)
    })
}

pub fn generate_mnemonic_from_entropy(entropy: &[u8]) -> Result<String> {
    dynamic_string(|out, out_len, out_written| unsafe {
        kms_generate_mnemonic_from_entropy(entropy.as_ptr(), entropy.len(), out, out_len, out_written)
    })
}

pub fn validate_mnemonic(phrase: &str) -> Result<()> {
    let c_phrase = CString::new(phrase)?;
    check(unsafe { kms_validate_mnemonic(c_phrase.as_ptr()) })
}

pub fn mnemonic_to_seed(phrase: &str, passphrase: &str) -> Result<Vec<u8>> {
    let c_phrase = CString::new(phrase)?;
    let c_passphrase = CString::new(passphrase)?;
    let mut out = vec![0u8; 64];
    let mut written = 0usize;
    check(unsafe {
        kms_mnemonic_to_seed(
            c_phrase.as_ptr(),
            c_passphrase.as_ptr(),
            out.as_mut_ptr(),
            out.len(),
            &mut written,
        )
    })?;
    out.truncate(written);
    Ok(out)
}

pub fn derive_private_key(
    mnemonic: &str,
    index: u32,
    account_index: u32,
    coin_type: u32,
    passphrase: &str,
) -> Result<KmsFelt> {
    let c_mnemonic = CString::new(mnemonic)?;
    let c_passphrase = CString::new(passphrase)?;
    let mut out = KmsFelt::default();

    check(unsafe {
        kms_derive_private_key_with_coin_type(
            c_mnemonic.as_ptr(),
            index,
            account_index,
            coin_type,
            c_passphrase.as_ptr(),
            &mut out,
        )
    })?;
    Ok(out)
}

pub fn derive_keypair(
    mnemonic: &str,
    index: u32,
    account_index: u32,
    coin_type: u32,
    passphrase: &str,
) -> Result<KmsTongoKeyPair> {
    let c_mnemonic = CString::new(mnemonic)?;
    let c_passphrase = CString::new(passphrase)?;
    let mut out = KmsTongoKeyPair::default();

    check(unsafe {
        kms_derive_keypair_with_coin_type(
            c_mnemonic.as_ptr(),
            index,
            account_index,
            coin_type,
            c_passphrase.as_ptr(),
            &mut out,
        )
    })?;
    Ok(out)
}

pub fn derive_view_private_key(
    mnemonic: &str,
    index: u32,
    account_index: u32,
    passphrase: &str,
) -> Result<KmsFelt> {
    let c_mnemonic = CString::new(mnemonic)?;
    let c_passphrase = CString::new(passphrase)?;
    let mut out = KmsFelt::default();

    check(unsafe {
        kms_derive_view_private_key(
            c_mnemonic.as_ptr(),
            index,
            account_index,
            c_passphrase.as_ptr(),
            &mut out,
        )
    })?;
    Ok(out)
}

pub fn derive_view_keypair(
    mnemonic: &str,
    index: u32,
    account_index: u32,
    passphrase: &str,
) -> Result<KmsTongoKeyPair> {
    let c_mnemonic = CString::new(mnemonic)?;
    let c_passphrase = CString::new(passphrase)?;
    let mut out = KmsTongoKeyPair::default();

    check(unsafe {
        kms_derive_view_keypair(
            c_mnemonic.as_ptr(),
            index,
            account_index,
            c_passphrase.as_ptr(),
            &mut out,
        )
    })?;
    Ok(out)
}

pub fn derive_nostr_private_key(
    mnemonic: &str,
    index: u32,
    account_index: u32,
    passphrase: &str,
) -> Result<[u8; 32]> {
    let c_mnemonic = CString::new(mnemonic)?;
    let c_passphrase = CString::new(passphrase)?;
    let mut out = [0u8; 32];

    check(unsafe {
        kms_derive_nostr_private_key(
            c_mnemonic.as_ptr(),
            index,
            account_index,
            c_passphrase.as_ptr(),
            out.as_mut_ptr(),
        )
    })?;
    Ok(out)
}

pub fn derive_nostr_keypair(
    mnemonic: &str,
    index: u32,
    account_index: u32,
    passphrase: &str,
) -> Result<KmsNostrKeyPair> {
    let c_mnemonic = CString::new(mnemonic)?;
    let c_passphrase = CString::new(passphrase)?;
    let mut out = KmsNostrKeyPair::default();

    check(unsafe {
        kms_derive_nostr_keypair(
            c_mnemonic.as_ptr(),
            index,
            account_index,
            c_passphrase.as_ptr(),
            &mut out,
        )
    })?;
    Ok(out)
}

pub fn calculate_contract_address(
    salt: &KmsFelt,
    class_hash: &KmsFelt,
    constructor_calldata: &[KmsFelt],
    deployer_address: &KmsFelt,
) -> Result<KmsFelt> {
    let mut out = KmsFelt::default();

    check(unsafe {
        kms_calculate_contract_address(
            salt,
            class_hash,
            constructor_calldata.as_ptr(),
            constructor_calldata.len(),
            deployer_address,
            &mut out,
        )
    })?;
    Ok(out)
}

pub fn derive_oz_account_address(
    public_key_x: &KmsFelt,
    class_hash: &KmsFelt,
    salt: Option<&KmsFelt>,
) -> Result<KmsFelt> {
    let mut out = KmsFelt::default();

    check(unsafe {
        kms_derive_oz_account_address(
            public_key_x,
            class_hash,
            salt.map_or(std::ptr::null(), |s| s as *const KmsFelt),
            &mut out,
        )
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coin_types_match_contract() {
        let (tongo, starknet, tongo_view, nostr) = coin_types();
        assert_eq!(tongo, 5454);
        assert_eq!(starknet, 9004);
        assert_eq!(tongo_view, 5353);
        assert_eq!(nostr, 1237);
    }

    #[test]
    fn felt_hex_roundtrip() {
        let felt = felt_from_hex("0x2a").expect("parse");
        let hex = felt_to_hex(&felt).expect("format");
        assert_eq!(
            hex,
            "0x000000000000000000000000000000000000000000000000000000000000002a"
        );
    }
}
