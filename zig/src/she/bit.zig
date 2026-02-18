const std = @import("std");
const core = @import("../core/root.zig");
const curve = @import("curve.zig");
const hash = @import("hash.zig");
const poe = @import("poe.zig");
const random = @import("random.zig");
const scalar = @import("scalar.zig");
const types = @import("types.zig");

pub const Error = error{
    InvalidBit,
    CryptoFailure,
    PointAtInfinity,
};

pub const ProveResult = struct {
    v: core.ProjectivePoint,
    proof: types.ProofOfBit,
};

fn xorFelt(a: core.Felt, b: core.Felt) core.Felt {
    const ab = a.toBytesBe();
    const bb = b.toBytesBe();
    var out: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        out[i] = ab[i] ^ bb[i];
    }
    return core.Felt.fromBytesBeUnchecked(out);
}

fn simulatePoe(y: core.ProjectivePoint, gen: core.ProjectivePoint) struct {
    a: core.ProjectivePoint,
    c: core.Felt,
    s: core.Felt,
} {
    const s = random.randomFelt();
    const c = random.randomFelt();
    const gen_s = curve.mul(s, gen);
    const y_c = curve.mul(c, y);
    const a = curve.add(gen_s, curve.neg(y_c));
    return .{ .a = a, .c = c, .s = s };
}

fn proveBit0(
    allocator: std.mem.Allocator,
    randomness: core.Felt,
    g1: core.ProjectivePoint,
    g2: core.ProjectivePoint,
    prefix: core.Felt,
) Error!ProveResult {
    const v = curve.mul(randomness, g2);
    const v1 = curve.add(v, curve.neg(g1));
    const sim = simulatePoe(v1, g2);

    const k = random.randomFelt();
    const a0 = curve.mul(k, g2);
    const c = hash.computePoseidonChallenge(allocator, prefix, &[_]core.ProjectivePoint{ a0, sim.a }) catch return Error.CryptoFailure;
    const c0 = xorFelt(c, sim.c);
    const s0 = scalar.scalarAdd(k, scalar.scalarMul(c0, randomness));

    return .{
        .v = v,
        .proof = .{
            .a0 = a0,
            .a1 = sim.a,
            .c0 = c0,
            .s0 = s0,
            .s1 = sim.s,
        },
    };
}

fn proveBit1(
    allocator: std.mem.Allocator,
    randomness: core.Felt,
    g1: core.ProjectivePoint,
    g2: core.ProjectivePoint,
    prefix: core.Felt,
) Error!ProveResult {
    const v = curve.add(g1, curve.mul(randomness, g2));
    const sim = simulatePoe(v, g2);

    const k = random.randomFelt();
    const a1 = curve.mul(k, g2);
    const c = hash.computePoseidonChallenge(allocator, prefix, &[_]core.ProjectivePoint{ sim.a, a1 }) catch return Error.CryptoFailure;
    const c1 = xorFelt(c, sim.c);
    const s1 = scalar.scalarAdd(k, scalar.scalarMul(c1, randomness));

    return .{
        .v = v,
        .proof = .{
            .a0 = sim.a,
            .a1 = a1,
            .c0 = sim.c,
            .s0 = sim.s,
            .s1 = s1,
        },
    };
}

pub fn prove(
    allocator: std.mem.Allocator,
    bit: u8,
    randomness: core.Felt,
    g1: core.ProjectivePoint,
    g2: core.ProjectivePoint,
    prefix: core.Felt,
) Error!ProveResult {
    return switch (bit) {
        0 => proveBit0(allocator, randomness, g1, g2, prefix),
        1 => proveBit1(allocator, randomness, g1, g2, prefix),
        else => Error.InvalidBit,
    };
}

pub fn verify(
    allocator: std.mem.Allocator,
    v: core.ProjectivePoint,
    g1: core.ProjectivePoint,
    g2: core.ProjectivePoint,
    proof: types.ProofOfBit,
    prefix: core.Felt,
) Error!bool {
    const c = hash.computePoseidonChallenge(
        allocator,
        prefix,
        &[_]core.ProjectivePoint{ proof.a0, proof.a1 },
    ) catch return Error.CryptoFailure;
    const c1 = xorFelt(c, proof.c0);

    const ok0 = poe.verifyInternal(v, g2, proof.a0, proof.c0, proof.s0) catch return Error.CryptoFailure;
    if (!ok0) return false;

    const v1 = curve.add(v, curve.neg(g1));
    const ok1 = poe.verifyInternal(v1, g2, proof.a1, c1, proof.s1) catch return Error.CryptoFailure;
    return ok1;
}
