const std = @import("std");
const core = @import("../core/root.zig");
const bit = @import("bit.zig");
const curve = @import("curve.zig");
const random = @import("random.zig");
const scalar = @import("scalar.zig");
const types = @import("types.zig");

pub const Error = error{
    InvalidInput,
    OutOfMemory,
    CryptoFailure,
};

pub const ProveResult = struct {
    range: types.RangeProof,
    randomness: core.Felt,
};

pub fn prove(
    allocator: std.mem.Allocator,
    value: u128,
    bit_size: usize,
    g1: core.ProjectivePoint,
    g2: core.ProjectivePoint,
    initial_prefix: core.Felt,
) Error!ProveResult {
    if (bit_size == 0 or bit_size > 128) return Error.InvalidInput;
    const max_value: u128 = if (bit_size == 128) std.math.maxInt(u128) else (@as(u128, 1) << @intCast(bit_size)) - 1;
    if (value > max_value) return Error.InvalidInput;

    const commitments = allocator.alloc(core.ProjectivePoint, bit_size) catch return Error.OutOfMemory;
    errdefer allocator.free(commitments);
    const proofs = allocator.alloc(types.ProofOfBit, bit_size) catch return Error.OutOfMemory;
    errdefer allocator.free(proofs);

    // Match Rust ordering: pre-generate all per-bit randomness before any bit proofs.
    const random_values = random.randomFelts(allocator, bit_size) catch return Error.OutOfMemory;
    defer allocator.free(random_values);

    var r_total = core.Felt.ZERO;
    var i: usize = 0;
    while (i < bit_size) : (i += 1) {
        const bit_value: u8 = @intCast((value >> @intCast(i)) & 1);
        const r_i = random_values[i];
        const idx_felt = core.Felt.fromU64(@intCast(i));
        const prefix = scalar.scalarAdd(initial_prefix, idx_felt);
        const res = bit.prove(allocator, bit_value, r_i, g1, g2, prefix) catch return Error.CryptoFailure;
        commitments[i] = res.v;
        proofs[i] = res.proof;

        const pow_int: u256 = @as(u256, 1) << @intCast(i);
        const pow_felt = core.Felt.fromInt(pow_int) catch return Error.CryptoFailure;
        const r_i_pow = scalar.scalarMul(pow_felt, r_i);
        r_total = scalar.scalarAdd(r_total, r_i_pow);
    }

    return .{
        .range = .{
            .commitments = commitments,
            .proofs = proofs,
        },
        .randomness = r_total,
    };
}

pub fn verify(
    allocator: std.mem.Allocator,
    range: types.RangeProof,
    bit_size: usize,
    g1: core.ProjectivePoint,
    g2: core.ProjectivePoint,
    initial_prefix: core.Felt,
) Error!core.ProjectivePoint {
    if (range.commitments.len != bit_size or range.proofs.len != bit_size) {
        return Error.InvalidInput;
    }
    if (bit_size == 0) return Error.InvalidInput;

    var v_total = range.commitments[0];
    const prefix0 = scalar.scalarAdd(initial_prefix, core.Felt.ZERO);
    const ok0 = bit.verify(
        allocator,
        v_total,
        g1,
        g2,
        range.proofs[0],
        prefix0,
    ) catch return Error.CryptoFailure;
    if (!ok0) return Error.CryptoFailure;

    var i: usize = 1;
    while (i < bit_size) : (i += 1) {
        const v = range.commitments[i];
        const prefix = scalar.scalarAdd(initial_prefix, core.Felt.fromU64(@intCast(i)));
        const ok = bit.verify(allocator, v, g1, g2, range.proofs[i], prefix) catch return Error.CryptoFailure;
        if (!ok) return Error.CryptoFailure;

        const pow_int: u256 = @as(u256, 1) << @intCast(i);
        const pow_felt = core.Felt.fromInt(pow_int) catch return Error.CryptoFailure;
        const v_pow = curve.mul(pow_felt, v);
        v_total = curve.add(v_total, v_pow);
    }

    return v_total;
}
