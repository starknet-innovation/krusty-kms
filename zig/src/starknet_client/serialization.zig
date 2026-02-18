const std = @import("std");
const core = @import("../core/root.zig");
const she = @import("../she/root.zig");
const tongo_ops = @import("../tongo/operations.zig");

pub const Error = error{
    InvalidPoint,
    InvalidInput,
    OutOfMemory,
};

pub fn serializeProjectivePoint(point: core.ProjectivePoint) Error![2]core.Felt {
    const affine = point.toAffine() orelse return Error.InvalidPoint;
    return .{ affine.x, affine.y };
}

pub fn deserializeProjectivePoint(x: core.Felt, y: core.Felt) Error!core.ProjectivePoint {
    if (!core.AffinePoint.new(x, y).isOnCurve()) return Error.InvalidPoint;
    return core.ProjectivePoint.fromAffine(x, y);
}

pub fn serializePoeProof(proof: she.types.PoeProof) Error![3]core.Felt {
    const a = try serializeProjectivePoint(proof.a);
    return .{ a[0], a[1], proof.s };
}

pub fn serializePoe2Proof(proof: she.types.Poe2Proof) Error![4]core.Felt {
    const a = try serializeProjectivePoint(proof.a);
    return .{ a[0], a[1], proof.s1, proof.s2 };
}

pub fn serializeElgamalProof(proof: she.types.ElGamalProof) Error![6]core.Felt {
    const al = try serializeProjectivePoint(proof.al);
    const ar = try serializeProjectivePoint(proof.ar);
    return .{ al[0], al[1], ar[0], ar[1], proof.sb, proof.sr };
}

pub fn u128ToU256(value: u128) [2]core.Felt {
    return .{
        feltFromU128(value),
        core.Felt.ZERO,
    };
}

pub fn u256ToU128(low: core.Felt, high: core.Felt) Error!u128 {
    if (!core.Felt.eql(high, core.Felt.ZERO)) return Error.InvalidInput;
    const bytes = low.toBytesBe();
    return std.mem.readInt(u128, bytes[16..32], .big);
}

pub fn serializeAeBalance(
    ciphertext_bytes: [64]u8,
    nonce_bytes: [24]u8,
) [6]core.Felt {
    const ct_felts = bytesToU512(ciphertext_bytes);

    var nonce_padded: [32]u8 = [_]u8{0} ** 32;
    @memcpy(nonce_padded[0..24], &nonce_bytes);
    const nonce_felts = bytesToU256(nonce_padded);

    return .{
        ct_felts[0],
        ct_felts[1],
        ct_felts[2],
        ct_felts[3],
        nonce_felts[0],
        nonce_felts[1],
    };
}

pub fn serializeAuditProof(proof: she.types.AuditProof) Error![11]core.Felt {
    const ax = try serializeProjectivePoint(proof.ax);
    const al0 = try serializeProjectivePoint(proof.al0);
    const al1 = try serializeProjectivePoint(proof.al1);
    const ar1 = try serializeProjectivePoint(proof.ar1);
    return .{
        ax[0],  ax[1],
        al0[0], al0[1],
        al1[0], al1[1],
        ar1[0], ar1[1],
        proof.sx, proof.sb, proof.sr,
    };
}

pub fn serializeCipherBalance(cipher: she.types.ElGamalCiphertext) Error![4]core.Felt {
    const l = try serializeProjectivePoint(cipher.l);
    const r = try serializeProjectivePoint(cipher.r);
    return .{ l[0], l[1], r[0], r[1] };
}

pub fn serializeBitProof(proof: she.types.ProofOfBit) Error![7]core.Felt {
    const a0 = try serializeProjectivePoint(proof.a0);
    const a1 = try serializeProjectivePoint(proof.a1);
    return .{ a0[0], a0[1], a1[0], a1[1], proof.c0, proof.s0, proof.s1 };
}

pub fn serializeRange(
    allocator: std.mem.Allocator,
    range: she.types.RangeProof,
) Error![]core.Felt {
    var out: std.ArrayList(core.Felt) = .empty;
    defer out.deinit(allocator);

    out.append(allocator, core.Felt.fromU64(@intCast(range.commitments.len))) catch return Error.OutOfMemory;
    for (range.commitments) |commitment| {
        const c = serializeProjectivePoint(commitment) catch return Error.InvalidPoint;
        out.append(allocator, c[0]) catch return Error.OutOfMemory;
        out.append(allocator, c[1]) catch return Error.OutOfMemory;
    }

    out.append(allocator, core.Felt.fromU64(@intCast(range.proofs.len))) catch return Error.OutOfMemory;
    for (range.proofs) |proof| {
        const p = serializeBitProof(proof) catch return Error.InvalidPoint;
        for (p) |f| {
            out.append(allocator, f) catch return Error.OutOfMemory;
        }
    }

    return out.toOwnedSlice(allocator) catch return Error.OutOfMemory;
}

pub fn serializeProofOfTransfer(
    allocator: std.mem.Allocator,
    proof: tongo_ops.ProofOfTransfer,
) Error![]core.Felt {
    var out: std.ArrayList(core.Felt) = .empty;
    defer out.deinit(allocator);

    const points = [_]core.ProjectivePoint{
        proof.a_x, proof.a_r, proof.a_r2, proof.a_b,
        proof.a_b2, proof.a_v, proof.a_v2, proof.a_bar,
    };
    for (points) |point| {
        const serialized = serializeProjectivePoint(point) catch return Error.InvalidPoint;
        out.append(allocator, serialized[0]) catch return Error.OutOfMemory;
        out.append(allocator, serialized[1]) catch return Error.OutOfMemory;
    }

    const scalars = [_]core.Felt{ proof.s_x, proof.s_r, proof.s_b, proof.s_b2, proof.s_r2 };
    for (scalars) |scalar| {
        out.append(allocator, scalar) catch return Error.OutOfMemory;
    }

    const r_aux = serializeProjectivePoint(proof.r_aux) catch return Error.InvalidPoint;
    out.append(allocator, r_aux[0]) catch return Error.OutOfMemory;
    out.append(allocator, r_aux[1]) catch return Error.OutOfMemory;

    const range = serializeRange(allocator, proof.range) catch |err| switch (err) {
        error.OutOfMemory => return Error.OutOfMemory,
        else => return Error.InvalidInput,
    };
    defer allocator.free(range);
    for (range) |f| {
        out.append(allocator, f) catch return Error.OutOfMemory;
    }

    const r_aux2 = serializeProjectivePoint(proof.r_aux2) catch return Error.InvalidPoint;
    out.append(allocator, r_aux2[0]) catch return Error.OutOfMemory;
    out.append(allocator, r_aux2[1]) catch return Error.OutOfMemory;

    const range2 = serializeRange(allocator, proof.range2) catch |err| switch (err) {
        error.OutOfMemory => return Error.OutOfMemory,
        else => return Error.InvalidInput,
    };
    defer allocator.free(range2);
    for (range2) |f| {
        out.append(allocator, f) catch return Error.OutOfMemory;
    }

    return out.toOwnedSlice(allocator) catch return Error.OutOfMemory;
}

fn bytesToU512(bytes: [64]u8) [4]core.Felt {
    var limb0: [16]u8 = undefined;
    var limb1: [16]u8 = undefined;
    var limb2: [16]u8 = undefined;
    var limb3: [16]u8 = undefined;
    @memcpy(&limb0, bytes[0..16]);
    @memcpy(&limb1, bytes[16..32]);
    @memcpy(&limb2, bytes[32..48]);
    @memcpy(&limb3, bytes[48..64]);

    return .{
        feltFromU128(std.mem.readInt(u128, &limb0, .big)),
        feltFromU128(std.mem.readInt(u128, &limb1, .big)),
        feltFromU128(std.mem.readInt(u128, &limb2, .big)),
        feltFromU128(std.mem.readInt(u128, &limb3, .big)),
    };
}

fn bytesToU256(bytes: [32]u8) [2]core.Felt {
    var high_bytes: [16]u8 = undefined;
    var low_bytes: [16]u8 = undefined;
    @memcpy(&high_bytes, bytes[0..16]);
    @memcpy(&low_bytes, bytes[16..32]);
    return .{
        feltFromU128(std.mem.readInt(u128, &low_bytes, .big)),
        feltFromU128(std.mem.readInt(u128, &high_bytes, .big)),
    };
}

fn feltFromU128(value: u128) core.Felt {
    return core.Felt.fromInt(@as(u256, value)) catch unreachable;
}

