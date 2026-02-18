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
    proof: types.Poe2Proof,
};

pub fn prove(
    x1: core.Felt,
    x2: core.Felt,
    g1: core.ProjectivePoint,
    g2: core.ProjectivePoint,
    prefix: core.Felt,
) Error!ProofResult {
    const g1_x1 = curve.mul(x1, g1);
    const g2_x2 = curve.mul(x2, g2);
    const y = curve.add(g1_x1, g2_x2);

    const k1 = random.randomFelt();
    const k2 = random.randomFelt();
    const a = curve.add(curve.mul(k1, g1), curve.mul(k2, g2));

    const c = hash.computeChallengeSingle(prefix, a) catch return Error.CryptoFailure;
    const s1 = scalar.scalarAdd(k1, scalar.scalarMul(c, x1));
    const s2 = scalar.scalarAdd(k2, scalar.scalarMul(c, x2));

    return .{
        .y = y,
        .proof = .{
            .a = a,
            .s1 = s1,
            .s2 = s2,
            .c = c,
        },
    };
}

pub fn verify(
    y: core.ProjectivePoint,
    g1: core.ProjectivePoint,
    g2: core.ProjectivePoint,
    proof: types.Poe2Proof,
    prefix: core.Felt,
) Error!bool {
    const c_computed = hash.computeChallengeSingle(prefix, proof.a) catch return Error.CryptoFailure;
    if (!core.Felt.eql(proof.c, c_computed)) return false;
    return verifyInternal(y, g1, g2, proof.a, proof.c, proof.s1, proof.s2);
}

pub fn verifyInternal(
    y: core.ProjectivePoint,
    g1: core.ProjectivePoint,
    g2: core.ProjectivePoint,
    a: core.ProjectivePoint,
    c: core.Felt,
    s1: core.Felt,
    s2: core.Felt,
) Error!bool {
    const lhs = curve.add(curve.mul(s1, g1), curve.mul(s2, g2));
    const rhs = curve.add(a, curve.mul(c, y));
    return curve.pointEq(lhs, rhs);
}
