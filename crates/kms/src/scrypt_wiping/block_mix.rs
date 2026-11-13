//! Portable BlockMix adapted from RustCrypto/scrypt 0.12.0
//! `src/block_mix/soft.rs` (MIT OR Apache-2.0).

use salsa20::{
    cipher::{typenum::U4, StreamCipherCore},
    SalsaCore,
};
use zeroize::Zeroizing;

type Salsa20_8 = SalsaCore<U4>;

// The portable BlockMix operates in byte order and needs no SIMD shuffle.
pub(crate) fn shuffle_in(_input: &mut [u8]) {}
pub(crate) fn shuffle_out(_input: &mut [u8]) {}

/// Execute the `BlockMix` operation.
///
/// - `input`: the input vector. The length must be a multiple of 128.
/// - `output`: the output vector. Must be the same length as input.
pub(crate) fn scrypt_block_mix(input: &[u8], output: &mut [u8]) {
    debug_assert_eq!(input.len() % 128, 0, "input must be a multiple of 128");
    debug_assert_eq!(
        output.len(),
        input.len(),
        "output must be same length as input"
    );

    let mut x = Zeroizing::new([0u8; 64]);
    x.copy_from_slice(&input[input.len() - 64..]);

    let mut t = Zeroizing::new([0u8; 64]);

    for (i, chunk) in input.chunks(64).enumerate() {
        xor(&*x, chunk, &mut *t);

        let mut t2 = Zeroizing::new([0u32; 16]);

        for (c, b) in t.as_chunks::<4>().0.iter().zip(t2.iter_mut()) {
            *b = u32::from_le_bytes(*c);
        }

        Salsa20_8::from_raw_state(*t2).write_keystream_block((&mut *x).into());

        let pos = if i % 2 == 0 {
            (i / 2) * 64
        } else {
            (i / 2) * 64 + input.len() / 2
        };

        output[pos..pos + 64].copy_from_slice(&*x);
    }
}

fn xor(x: &[u8], y: &[u8], output: &mut [u8]) {
    for ((out, &x_i), &y_i) in output.iter_mut().zip(x.iter()).zip(y.iter()) {
        *out = x_i ^ y_i;
    }
}
