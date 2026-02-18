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

pub const ElGamalEncryption = struct {
    l: core.ProjectivePoint,
    r: core.ProjectivePoint,
    proof: types.ElGamalProof,
};

pub fn encrypt(
    message: core.Felt,
    public_key: core.ProjectivePoint,
    randomness: core.Felt,
    prefix: core.Felt,
) Error!ElGamalEncryption {
    const g_m = curve.mul(message, curve.GENERATOR);
    const pk_r = curve.mul(randomness, public_key);
    const l = curve.add(g_m, pk_r);
    const r = curve.mul(randomness, curve.GENERATOR);
    const proof = try proveEncryption(message, randomness, public_key, l, r, prefix);
    return .{ .l = l, .r = r, .proof = proof };
}

fn proveEncryption(
    message: core.Felt,
    randomness: core.Felt,
    public_key: core.ProjectivePoint,
    l: core.ProjectivePoint,
    r: core.ProjectivePoint,
    prefix: core.Felt,
) Error!types.ElGamalProof {
    const r_b = random.randomFelt();
    const r_r = random.randomFelt();

    const a_l = curve.add(curve.mul(r_b, curve.GENERATOR), curve.mul(r_r, public_key));
    const a_r = curve.mul(r_r, curve.GENERATOR);

    const c = hash.computeChallengeTriple(prefix, l, r, a_l) catch return Error.CryptoFailure;
    const sb = scalar.scalarAdd(r_b, scalar.scalarMul(c, message));
    const sr = scalar.scalarAdd(r_r, scalar.scalarMul(c, randomness));

    return .{
        .al = a_l,
        .ar = a_r,
        .sb = sb,
        .sr = sr,
        .c = c,
    };
}

pub fn verify(
    l: core.ProjectivePoint,
    r: core.ProjectivePoint,
    public_key: core.ProjectivePoint,
    proof: types.ElGamalProof,
    prefix: core.Felt,
) Error!bool {
    const c_computed = hash.computeChallengeTriple(prefix, l, r, proof.al) catch return Error.CryptoFailure;
    if (!core.Felt.eql(proof.c, c_computed)) return false;

    const lhs1 = curve.mul(proof.sr, curve.GENERATOR);
    const rhs1 = curve.add(proof.ar, curve.mul(proof.c, r));
    if (!curve.pointEq(lhs1, rhs1)) return false;

    const lhs2 = curve.add(curve.mul(proof.sb, curve.GENERATOR), curve.mul(proof.sr, public_key));
    const rhs2 = curve.add(proof.al, curve.mul(proof.c, l));
    return curve.pointEq(lhs2, rhs2);
}

pub fn decrypt(ciphertext: types.ElGamalCiphertext, private_key: core.Felt) Error!core.ProjectivePoint {
    const r_sk = curve.mul(private_key, ciphertext.r);
    const neg_r_sk = curve.neg(r_sk);
    return curve.add(ciphertext.l, neg_r_sk);
}
