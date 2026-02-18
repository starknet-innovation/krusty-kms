const std = @import("std");
const core = @import("../core/root.zig");
const curve = @import("curve.zig");
const hash = @import("hash.zig");
const rng = @import("rng.zig");
const scalar = @import("scalar.zig");
const types = @import("types.zig");

pub const AUDIT_CAIRO_STRING: core.Felt = core.Felt.fromU64(418_581_342_580);

pub const Error = error{
    InvalidInput,
    InvalidCiphertext,
    PointAtInfinity,
    CryptoFailure,
};

pub const AuditResult = struct {
    proof: types.AuditProof,
    cipher1: types.ElGamalCiphertext,
};

pub fn prove(
    allocator: std.mem.Allocator,
    private_key: core.Felt,
    balance: u128,
    cipher0: types.ElGamalCiphertext,
    auditor_pub_key: core.ProjectivePoint,
) Error!AuditResult {
    return proveWithValidation(allocator, private_key, balance, cipher0, auditor_pub_key, true);
}

pub fn proveWithValidation(
    allocator: std.mem.Allocator,
    private_key: core.Felt,
    balance: u128,
    cipher0: types.ElGamalCiphertext,
    auditor_pub_key: core.ProjectivePoint,
    validate: bool,
) Error!AuditResult {
    if (curve.isInfinity(cipher0.l) or curve.isInfinity(cipher0.r) or curve.isInfinity(auditor_pub_key)) {
        return Error.InvalidInput;
    }

    if (validate) {
        const r0_x = curve.mul(private_key, cipher0.r);
        const g_b_computed = curve.add(cipher0.l, curve.neg(r0_x));
        const g_b_expected = curve.mul(feltFromU128(balance), curve.GENERATOR);
        if (!curve.pointEq(g_b_computed, g_b_expected)) return Error.InvalidCiphertext;
    }

    const r1 = randomAuditFelt();
    const auditor_r1 = curve.mul(r1, auditor_pub_key);

    const l1 = if (balance == 0)
        auditor_r1
    else
        curve.add(curve.mul(feltFromU128(balance), curve.GENERATOR), auditor_r1);

    const r1_point = curve.mul(r1, curve.GENERATOR);
    if (curve.isInfinity(l1) or curve.isInfinity(r1_point)) return Error.InvalidInput;

    const cipher1 = types.ElGamalCiphertext{
        .l = l1,
        .r = r1_point,
    };

    const kx = randomAuditFelt();
    const kb = randomAuditFelt();
    const kr = randomAuditFelt();

    const ax = curve.mul(kx, curve.GENERATOR);
    const g_kb = curve.mul(kb, curve.GENERATOR);
    const r0_kx = curve.mul(kx, cipher0.r);
    const al0 = curve.add(g_kb, r0_kx);
    const ar1 = curve.mul(kr, curve.GENERATOR);
    const al1 = curve.add(g_kb, curve.mul(kr, auditor_pub_key));

    if (curve.isInfinity(ax) or curve.isInfinity(al0) or curve.isInfinity(al1) or curve.isInfinity(ar1)) {
        return Error.InvalidInput;
    }

    const c = hash.computePoseidonChallenge(
        allocator,
        AUDIT_CAIRO_STRING,
        &[_]core.ProjectivePoint{ ax, al0, al1, ar1 },
    ) catch |err| switch (err) {
        error.PointAtInfinity => return Error.PointAtInfinity,
        else => return Error.CryptoFailure,
    };

    const sx = scalar.scalarAdd(kx, scalar.scalarMul(c, private_key));
    const sb = scalar.scalarAdd(kb, scalar.scalarMul(c, feltFromU128(balance)));
    const sr = scalar.scalarAdd(kr, scalar.scalarMul(c, r1));

    const proof = types.AuditProof{
        .ax = ax,
        .al0 = al0,
        .al1 = al1,
        .ar1 = ar1,
        .sx = sx,
        .sb = sb,
        .sr = sr,
        .c = c,
    };

    return .{
        .proof = proof,
        .cipher1 = cipher1,
    };
}

pub fn verify(
    allocator: std.mem.Allocator,
    proof: types.AuditProof,
    user_pub_key: core.ProjectivePoint,
    cipher0: types.ElGamalCiphertext,
    cipher1: types.ElGamalCiphertext,
    auditor_pub_key: core.ProjectivePoint,
) Error!bool {
    const c_computed = hash.computePoseidonChallenge(
        allocator,
        AUDIT_CAIRO_STRING,
        &[_]core.ProjectivePoint{ proof.ax, proof.al0, proof.al1, proof.ar1 },
    ) catch |err| switch (err) {
        error.PointAtInfinity => return Error.PointAtInfinity,
        else => return Error.CryptoFailure,
    };
    if (!core.Felt.eql(proof.c, c_computed)) return false;

    const lhs1 = curve.mul(proof.sx, curve.GENERATOR);
    const rhs1 = curve.add(proof.ax, curve.mul(proof.c, user_pub_key));
    if (!curve.pointEq(lhs1, rhs1)) return false;

    const g_sb = curve.mul(proof.sb, curve.GENERATOR);
    const lhs2 = curve.add(g_sb, curve.mul(proof.sx, cipher0.r));
    const rhs2 = curve.add(proof.al0, curve.mul(proof.c, cipher0.l));
    if (!curve.pointEq(lhs2, rhs2)) return false;

    const lhs3 = curve.mul(proof.sr, curve.GENERATOR);
    const rhs3 = curve.add(proof.ar1, curve.mul(proof.c, cipher1.r));
    if (!curve.pointEq(lhs3, rhs3)) return false;

    const lhs4 = curve.add(g_sb, curve.mul(proof.sr, auditor_pub_key));
    const rhs4 = curve.add(proof.al1, curve.mul(proof.c, cipher1.l));
    if (!curve.pointEq(lhs4, rhs4)) return false;

    return true;
}

fn feltFromU128(value: u128) core.Felt {
    return core.Felt.fromInt(@as(u256, value)) catch unreachable;
}

fn randomAuditFelt() core.Felt {
    // Match she-core::audit::AuditProver::random_felt:
    // sample 32 bytes, mask high nibble, parse as felt.
    var bytes: [32]u8 = undefined;
    rng.fillBytes(&bytes);
    bytes[0] &= 0x0f;
    return core.Felt.fromBytesBeUnchecked(bytes);
}
