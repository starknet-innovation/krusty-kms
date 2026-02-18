const core = @import("../core/root.zig");

pub const types = @import("types.zig");
pub const scalar = @import("scalar.zig");
pub const rng = @import("rng.zig");
pub const random = @import("random.zig");
pub const curve = @import("curve.zig");
pub const hash = @import("hash.zig");
pub const poe = @import("poe.zig");
pub const poe2 = @import("poe2.zig");
pub const elgamal = @import("elgamal.zig");
pub const bit = @import("bit.zig");
pub const range = @import("range.zig");
pub const audit = @import("audit.zig");

pub const ElGamalCiphertext = types.ElGamalCiphertext;
pub const PoeProof = types.PoeProof;
pub const Poe2Proof = types.Poe2Proof;
pub const ElGamalProof = types.ElGamalProof;
pub const ProofOfBit = types.ProofOfBit;
pub const RangeProof = types.RangeProof;
pub const AuditProof = types.AuditProof;

pub const GENERATOR = curve.GENERATOR;
pub const GENERATOR_H = curve.GENERATOR_H;

pub fn poseidonHashMany(inputs: []const core.Felt) hash.Error!core.Felt {
    return hash.poseidonHashMany(inputs);
}
