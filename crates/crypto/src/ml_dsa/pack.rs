//! Packing into the felt layout the Cairo account verifier reads.
//!
//! One rule governs every function here: a felt is built as two u128 halves,
//! `low + (high << 128)`. Every layout this module emits keeps each half under
//! 2^124 (the widest is six 20-bit fields, 120 bits), so the composed value
//! stays below 2^252 and is always a valid felt. The composition is done by
//! writing 32 big-endian bytes rather than by field arithmetic, so it is exact
//! integer packing with no reduction anywhere.

use starknet_types_core::felt::Felt;

// `high` occupies the top 16 bytes and `low` the bottom 16, which is exactly
// `low + (high << 128)` for any pair under 2^128.
fn compose(low: u128, high: u128) -> Felt {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&high.to_be_bytes());
    bytes[16..].copy_from_slice(&low.to_be_bytes());
    Felt::from_bytes_be(&bytes)
}

// Packs `per_half` values into each half of a felt, at `bits` each. A short
// final group is zero-filled, which is what makes 1,536 coefficients pack into
// 154 felts rather than requiring a multiple of the group size.
fn pack_halves(values: &[u128], bits: u32, per_half: usize) -> Vec<Felt> {
    let per_felt = 2 * per_half;
    let mut felts = Vec::with_capacity(values.len().div_ceil(per_felt));
    let mut group = 0usize;
    while group < values.len() {
        let mut low = 0u128;
        let mut high = 0u128;
        for slot in 0..per_half {
            let shift = bits * slot as u32;
            low += values.get(group + slot).copied().unwrap_or(0) << shift;
            high += values.get(group + per_half + slot).copied().unwrap_or(0) << shift;
        }
        felts.push(compose(low, high));
        group += per_felt;
    }
    felts
}

/// Packs coefficients ten to a felt: five 23-bit fields in each u128 half.
pub(super) fn pack_coeffs(coefficients: &[u128]) -> Vec<Felt> {
    pack_halves(coefficients, 23, 5)
}

/// Packs values `per_half` to each u128 half of a felt, at `bits` each.
pub(super) fn pack_fields(values: &[u128], bits: u32, per_half: usize) -> Vec<Felt> {
    pack_halves(values, bits, per_half)
}

/// Packs bytes 31 to a felt: 16 little-endian in the low u128, 15 in the high.
pub(super) fn pack_bytes(data: &[u8]) -> Vec<Felt> {
    let mut felts = Vec::with_capacity(data.len().div_ceil(31));
    let mut group = 0usize;
    while group < data.len() {
        felts.push(compose(
            little_endian(data, group, 16),
            little_endian(data, group + 16, 15),
        ));
        group += 31;
    }
    felts
}

// Reads up to `length` bytes little-endian, treating anything past the end as
// zero. The final group of a 64-byte `tr` is partial, and zero-filling it is
// what makes the packed key 925 felts.
fn little_endian(data: &[u8], offset: usize, length: usize) -> u128 {
    let mut value = 0u128;
    for index in (0..length).rev() {
        value = (value << 8) | u128::from(data.get(offset + index).copied().unwrap_or(0));
    }
    value
}
