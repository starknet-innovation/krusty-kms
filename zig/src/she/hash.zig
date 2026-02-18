const std = @import("std");
const core = @import("../core/root.zig");
const scalar = @import("scalar.zig");
const crypto = @import("../crypto/root.zig");

pub const Error = error{
    PointAtInfinity,
    CryptoFailure,
};

const MAX_BATCH_POINTS: usize = 128;

pub fn computeChallenge(prefix: core.Felt, points: []const core.ProjectivePoint) Error!core.Felt {
    if (points.len > MAX_BATCH_POINTS) return Error.CryptoFailure;

    var affines: [MAX_BATCH_POINTS]core.AffinePoint = undefined;
    try batchToAffine(points, affines[0..points.len]);

    var current = prefix;
    for (affines[0..points.len]) |affine| {
        current = crypto.pedersen.hash(current, affine.x) catch return Error.CryptoFailure;
        current = crypto.pedersen.hash(current, affine.y) catch return Error.CryptoFailure;
    }
    return current;
}

pub fn computeChallengeSingle(prefix: core.Felt, point: core.ProjectivePoint) Error!core.Felt {
    return computeChallenge(prefix, &[_]core.ProjectivePoint{point});
}

pub fn computeChallengePair(
    prefix: core.Felt,
    p1: core.ProjectivePoint,
    p2: core.ProjectivePoint,
) Error!core.Felt {
    return computeChallenge(prefix, &[_]core.ProjectivePoint{ p1, p2 });
}

pub fn computeChallengeTriple(
    prefix: core.Felt,
    p1: core.ProjectivePoint,
    p2: core.ProjectivePoint,
    p3: core.ProjectivePoint,
) Error!core.Felt {
    return computeChallenge(prefix, &[_]core.ProjectivePoint{ p1, p2, p3 });
}

pub fn hashFelts(felts: []const core.Felt) Error!core.Felt {
    var current = core.Felt.ZERO;
    for (felts) |felt| {
        current = crypto.pedersen.hash(current, felt) catch return Error.CryptoFailure;
    }
    return current;
}

pub fn poseidonHashMany(felts: []const core.Felt) Error!core.Felt {
    return crypto.poseidon.hashMany(felts) catch Error.CryptoFailure;
}

pub fn computePoseidonChallenge(
    _: std.mem.Allocator,
    prefix: core.Felt,
    points: []const core.ProjectivePoint,
) Error!core.Felt {
    const needed = 1 + (points.len * 2);
    if (needed > 65 or points.len > MAX_BATCH_POINTS) return Error.CryptoFailure;

    var values: [65]core.Felt = undefined;
    var affines: [MAX_BATCH_POINTS]core.AffinePoint = undefined;
    try batchToAffine(points, affines[0..points.len]);

    var values_len: usize = 0;
    values[values_len] = prefix;
    values_len += 1;

    for (affines[0..points.len]) |affine| {
        values[values_len] = affine.x;
        values_len += 1;
        values[values_len] = affine.y;
        values_len += 1;
    }

    const h = crypto.poseidon.hashMany(values[0..values_len]) catch return Error.CryptoFailure;
    return scalar.reduceScalar(h);
}

fn batchToAffine(points: []const core.ProjectivePoint, out: []core.AffinePoint) Error!void {
    if (points.len != out.len) return Error.CryptoFailure;
    if (points.len == 0) return;

    var prefixes: [MAX_BATCH_POINTS]core.Felt = undefined;
    var acc = core.Felt.ONE;

    for (points, 0..) |point, i| {
        if (point.isIdentity()) return Error.PointAtInfinity;
        prefixes[i] = acc;
        acc = acc.mul(point.z);
    }

    var inv_acc = acc.inverse() catch return Error.CryptoFailure;
    var i: usize = points.len;
    while (i > 0) {
        i -= 1;
        const point = points[i];
        const inv_z = inv_acc.mul(prefixes[i]);
        inv_acc = inv_acc.mul(point.z);

        const z2 = inv_z.square();
        const z3 = z2.mul(inv_z);
        out[i] = core.AffinePoint.new(point.x.mul(z2), point.y.mul(z3));
    }
}
