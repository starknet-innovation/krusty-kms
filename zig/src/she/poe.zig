const std = @import("std");
const core = @import("../core/root.zig");
const curve = @import("curve.zig");
const hash = @import("hash.zig");
const scalar = @import("scalar.zig");
const random = @import("random.zig");
const types = @import("types.zig");

pub const Error = error{
    CryptoFailure,
    PointAtInfinity,
};

pub const ProofResult = struct {
    y: core.ProjectivePoint,
    proof: types.PoeProof,
};

pub fn prove(
    allocator: std.mem.Allocator,
    x: core.Felt,
    prefix: core.Felt,
) Error!ProofResult {
    const y = curve.mul(x, curve.GENERATOR);
    const r = random.randomFelt();
    const a = curve.mul(r, curve.GENERATOR);
    const c = hash.computePoseidonChallenge(allocator, prefix, &[_]core.ProjectivePoint{a}) catch {
        return Error.CryptoFailure;
    };
    const s = scalar.scalarAdd(r, scalar.scalarMul(c, x));

    return .{
        .y = y,
        .proof = .{
            .a = a,
            .s = s,
            .c = c,
        },
    };
}

pub fn verify(
    allocator: std.mem.Allocator,
    y: core.ProjectivePoint,
    proof: types.PoeProof,
    prefix: core.Felt,
) Error!bool {
    const c_computed = hash.computePoseidonChallenge(allocator, prefix, &[_]core.ProjectivePoint{proof.a}) catch {
        return Error.CryptoFailure;
    };
    if (!core.Felt.eql(proof.c, c_computed)) return false;
    return verifyInternal(y, curve.GENERATOR, proof.a, proof.c, proof.s);
}

pub fn verifyInternal(
    y: core.ProjectivePoint,
    gen: core.ProjectivePoint,
    a: core.ProjectivePoint,
    c: core.Felt,
    s: core.Felt,
) Error!bool {
    const lhs = curve.mul(s, gen);
    const y_c = curve.mul(c, y);
    const rhs = curve.add(a, y_c);
    return curve.pointEq(lhs, rhs);
}

