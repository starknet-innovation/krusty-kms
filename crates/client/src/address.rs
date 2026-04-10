//! TongoAddress: base58-encoded compressed public key.
//!
//! Uses SEC1 compressed point format (33 bytes) with standard base58 (Bitcoin alphabet).

use krusty_kms_common::{KmsError, Result};
use starknet_types_core::curve::ProjectivePoint;
use starknet_types_core::felt::Felt;

/// Stark curve β parameter: y² = x³ + x + β
const STARK_BETA: Felt =
    Felt::from_hex_unchecked("0x6f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89");

/// Encode a public key as a TongoAddress (base58-encoded compressed point).
pub fn pub_key_to_tongo_address(pub_key: &ProjectivePoint) -> Result<String> {
    let bytes = compress_point(pub_key)?;
    Ok(bs58::encode(bytes).into_string())
}

/// Decode a TongoAddress back to a ProjectivePoint.
pub fn tongo_address_to_pub_key(address: &str) -> Result<ProjectivePoint> {
    let bytes = bs58::decode(address)
        .into_vec()
        .map_err(|e| KmsError::DeserializationError(format!("Invalid base58: {e}")))?;

    if bytes.len() != 33 {
        return Err(KmsError::DeserializationError(format!(
            "Expected 33 bytes for compressed point, got {}",
            bytes.len()
        )));
    }

    decompress_point(&bytes)
}

/// Encode a public key as a hex string (compressed format).
#[allow(dead_code)]
pub fn pub_key_to_hex(pub_key: &ProjectivePoint) -> Result<String> {
    let bytes = compress_point(pub_key)?;
    Ok(format!("0x{}", hex::encode(bytes)))
}

/// Compress a ProjectivePoint to 33-byte SEC1 format.
fn compress_point(point: &ProjectivePoint) -> Result<[u8; 33]> {
    let affine = point
        .to_affine()
        .map_err(|_| KmsError::CryptoError("Cannot compress point at infinity".to_string()))?;

    let x_bytes = affine.x().to_bytes_be();
    let y_bytes = affine.y().to_bytes_be();

    // Prefix: 0x02 if y is even, 0x03 if y is odd
    let prefix = if y_bytes[31] & 1 == 0 { 0x02 } else { 0x03 };

    let mut result = [0u8; 33];
    result[0] = prefix;
    result[1..33].copy_from_slice(&x_bytes);
    Ok(result)
}

/// Decompress a 33-byte SEC1 compressed point.
fn decompress_point(bytes: &[u8]) -> Result<ProjectivePoint> {
    let prefix = bytes[0];
    if prefix != 0x02 && prefix != 0x03 {
        return Err(KmsError::DeserializationError(format!(
            "Invalid compression prefix: 0x{prefix:02x}"
        )));
    }

    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&bytes[1..33]);
    let x = Felt::from_bytes_be(&x_bytes);

    // Compute y² = x³ + α·x + β (α=1 on the Stark curve)
    let x2 = x * x;
    let x3 = x2 * x;
    let y_squared = x3 + x + STARK_BETA;

    // Use Felt::sqrt() which handles the Stark field correctly
    let y = y_squared.sqrt().ok_or_else(|| {
        KmsError::CryptoError("x-coordinate is not on the Stark curve".to_string())
    })?;

    // Choose correct y parity based on prefix
    let y_bytes = y.to_bytes_be();
    let y_is_odd = y_bytes[31] & 1 == 1;
    let want_odd = prefix == 0x03;

    let final_y = if y_is_odd == want_odd {
        y
    } else {
        Felt::ZERO - y
    };

    ProjectivePoint::from_affine(x, final_y)
        .map_err(|_| KmsError::CryptoError("Decompressed point not on curve".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generator() -> ProjectivePoint {
        let g_x = Felt::from_hex_unchecked(
            "0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca",
        );
        let g_y = Felt::from_hex_unchecked(
            "0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f",
        );
        ProjectivePoint::from_affine(g_x, g_y).unwrap()
    }

    #[test]
    fn test_compress_decompress_roundtrip() {
        let point = generator();
        let compressed = compress_point(&point).unwrap();
        let decompressed = decompress_point(&compressed).unwrap();

        let orig = point.to_affine().unwrap();
        let back = decompressed.to_affine().unwrap();
        assert_eq!(orig.x(), back.x());
        assert_eq!(orig.y(), back.y());
    }

    #[test]
    fn test_tongo_address_roundtrip() {
        let point = generator();
        let address = pub_key_to_tongo_address(&point).unwrap();
        let recovered = tongo_address_to_pub_key(&address).unwrap();

        let orig = point.to_affine().unwrap();
        let back = recovered.to_affine().unwrap();
        assert_eq!(orig.x(), back.x());
        assert_eq!(orig.y(), back.y());
    }

    #[test]
    fn test_tongo_address_roundtrip_2g() {
        // Test with 2*G (different parity)
        let g = generator();
        let point = &g + &g;
        let address = pub_key_to_tongo_address(&point).unwrap();
        let recovered = tongo_address_to_pub_key(&address).unwrap();

        let orig = point.to_affine().unwrap();
        let back = recovered.to_affine().unwrap();
        assert_eq!(orig.x(), back.x());
        assert_eq!(orig.y(), back.y());
    }

    #[test]
    fn test_pub_key_to_hex() {
        let point = generator();
        let hex_str = pub_key_to_hex(&point).unwrap();
        assert!(hex_str.starts_with("0x"));
        // 33 bytes = 66 hex chars + "0x" prefix
        assert_eq!(hex_str.len(), 68);
    }

    #[test]
    fn test_invalid_base58() {
        let result = tongo_address_to_pub_key("0OIl"); // invalid base58 chars
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_length() {
        let result = tongo_address_to_pub_key("1111"); // too short
        assert!(result.is_err());
    }

    #[test]
    fn test_felt_sqrt_known_value() {
        // 4's sqrt should satisfy root*root == 4 (mod p)
        let four = Felt::from(4u64);
        let root = four.sqrt().unwrap();
        assert_eq!(root * root, four);
    }

    #[test]
    fn test_compress_prefix_parity() {
        let point = generator();
        let compressed = compress_point(&point).unwrap();
        let affine = point.to_affine().unwrap();
        let y_bytes = affine.y().to_bytes_be();
        let expected_prefix = if y_bytes[31] & 1 == 0 { 0x02 } else { 0x03 };
        assert_eq!(compressed[0], expected_prefix);
    }
}
