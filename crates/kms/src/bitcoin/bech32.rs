//! BIP-173 bech32 encoding of segwit version 0 addresses.
//!
//! Only encoding is needed: callers compare a supplied address against the
//! encoding of their own key, which is exact because bech32 is a bijection
//! between canonical strings and (hrp, version, program).

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATORS: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];
/// BIP-173 checksum constant (bech32, not the BIP-350 bech32m constant).
const BECH32_CONST: u32 = 1;

/// Encode a segwit v0 program as a lowercase bech32 address.
pub(super) fn encode_segwit_v0(hrp: &str, program: &[u8]) -> String {
    let mut data = vec![0u8];
    data.extend(to_base32(program));

    let checksum = checksum(hrp.as_bytes(), &data);
    let mut address = String::with_capacity(hrp.len() + 1 + data.len() + checksum.len());
    address.push_str(hrp);
    address.push('1');
    for value in data.iter().chain(checksum.iter()) {
        address.push(char::from(CHARSET[usize::from(*value)]));
    }
    address
}

fn checksum(hrp: &[u8], data: &[u8]) -> [u8; 6] {
    let values = hrp
        .iter()
        .map(|c| c >> 5)
        .chain([0])
        .chain(hrp.iter().map(|c| c & 0x1f))
        .chain(data.iter().copied())
        .chain([0u8; 6]);
    let modulus = polymod(values) ^ BECH32_CONST;

    let mut checksum = [0u8; 6];
    for (i, value) in checksum.iter_mut().enumerate() {
        // Masked to five bits, so the cast cannot truncate.
        *value = ((modulus >> (5 * (5 - i))) & 0x1f) as u8;
    }
    checksum
}

fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    let mut chk: u32 = 1;
    for value in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(value);
        for (i, generator) in GENERATORS.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= generator;
            }
        }
    }
    chk
}

/// Regroup 8-bit bytes into 5-bit values, zero-padding the last group.
fn to_base32(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut accumulator: u32 = 0;
    let mut bits = 0u32;
    for byte in bytes {
        accumulator = ((accumulator << 8) | u32::from(*byte)) & 0xfff;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((accumulator >> bits) & 0x1f) as u8);
        }
    }
    if bits > 0 {
        out.push(((accumulator << (5 - bits)) & 0x1f) as u8);
    }
    out
}
