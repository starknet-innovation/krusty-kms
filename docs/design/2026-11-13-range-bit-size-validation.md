# Range bit-size validation

Range proofs require a nonempty width of at most 128 bits. Previously, a zero-width
proof could be constructed but verification indexed an empty commitment list;
oversized widths were rejected only after generating randomness. The public
`range::validate_bit_size` function gives the SDK's transfer and withdraw paths
the same check used by the primitive before either path starts proof work.

This is an additive API. Existing valid widths `1..=128` keep their proof format
and transcript. Invalid widths return `CryptoError` before randomness or indexing.
Tests cover the boundary widths and the zero-width verifier path.
