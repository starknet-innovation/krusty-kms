const core = @import("../core/root.zig");

pub const Error = error{
    PointAtInfinity,
    InvalidPoint,
};

pub const GENERATOR: core.ProjectivePoint = core.ProjectivePoint.generator();
pub const GENERATOR_H: core.ProjectivePoint = core.ProjectivePoint.fromAffine(
    core.Felt.fromHex("0x0162eb5cc8f50e522225785a604ba6d7e9ab06b647157f77c59a06032610b2d2") catch unreachable,
    core.Felt.fromHex("0x0220a56864c490175202e3e34db0e24d12979fbfacea16a360e8feb1f6749192") catch unreachable,
);

pub fn mul(scalar: core.Felt, point: ?core.ProjectivePoint) core.ProjectivePoint {
    const base = point orelse GENERATOR;
    return core.ProjectivePoint.scalarMulPublicVt(base, scalar);
}

pub fn mulPublicVt(scalar: core.Felt, point: ?core.ProjectivePoint) core.ProjectivePoint {
    const base = point orelse GENERATOR;
    return core.ProjectivePoint.scalarMulPublicVt(base, scalar);
}

pub fn mulSecretCt(scalar: core.Felt, point: ?core.ProjectivePoint) core.ProjectivePoint {
    const base = point orelse GENERATOR;
    return core.ProjectivePoint.scalarMulSecretCt(base, scalar);
}

pub fn mulGenerator(scalar: core.Felt) core.ProjectivePoint {
    return core.ProjectivePoint.scalarMulPublicVt(GENERATOR, scalar);
}

pub fn add(a: core.ProjectivePoint, b: core.ProjectivePoint) core.ProjectivePoint {
    return a.add(b);
}

pub fn affineToProjective(point: core.AffinePoint) core.ProjectivePoint {
    return core.ProjectivePoint.fromAffine(point.x, point.y);
}

pub fn projectiveToAffine(point: core.ProjectivePoint) Error!core.AffinePoint {
    return point.toAffine() orelse Error.PointAtInfinity;
}

pub fn isInfinity(point: core.ProjectivePoint) bool {
    return point.isIdentity();
}

pub fn isOnCurve(x: core.Felt, y: core.Felt) bool {
    return core.AffinePoint.new(x, y).isOnCurve();
}

pub fn pointEq(a: core.ProjectivePoint, b: core.ProjectivePoint) bool {
    if (a.isIdentity() and b.isIdentity()) return true;
    if (a.isIdentity() or b.isIdentity()) return false;

    const z1z1 = a.z.square();
    const z2z2 = b.z.square();
    const u1v = a.x.mul(z2z2);
    const u2v = b.x.mul(z1z1);
    if (!core.Felt.eql(u1v, u2v)) return false;

    const s1 = a.y.mul(b.z).mul(z2z2);
    const s2 = b.y.mul(a.z).mul(z1z1);
    return core.Felt.eql(s1, s2);
}

pub fn neg(p: core.ProjectivePoint) core.ProjectivePoint {
    if (p.isIdentity()) return p;
    return core.ProjectivePoint.newUnchecked(p.x, p.y.neg(), p.z);
}
