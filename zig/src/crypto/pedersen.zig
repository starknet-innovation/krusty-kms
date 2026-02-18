const core = @import("../core/root.zig");
const constants = @import("generated/pedersen_points.zig");

pub const Error = error{
    CryptoFailure,
};

pub fn hash(left: core.Felt, right: core.Felt) Error!core.Felt {
    const left_bytes = left.toBytesBe();
    const right_bytes = right.toBytesBe();

    var acc = core.ProjectivePoint.fromAffine(
        constants.SHIFT_POINT.x,
        constants.SHIFT_POINT.y,
    );

    lookupAndAccumulateFromBytes(&acc, left_bytes, 0, 248, &constants.POINTS_P1);
    lookupAndAccumulateFromBytes(&acc, left_bytes, 248, 4, &constants.POINTS_P2);
    lookupAndAccumulateFromBytes(&acc, right_bytes, 0, 248, &constants.POINTS_P3);
    lookupAndAccumulateFromBytes(&acc, right_bytes, 248, 4, &constants.POINTS_P4);

    const affine = acc.toAffine() orelse return Error.CryptoFailure;
    return affine.x;
}

fn lookupAndAccumulateFromBytes(
    acc: *core.ProjectivePoint,
    bytes_be: [32]u8,
    bit_start: usize,
    bit_len: usize,
    table: []const core.AffinePoint,
) void {
    const chunks = bit_len / 4;
    var chunk_i: usize = 0;
    while (chunk_i < chunks) : (chunk_i += 1) {
        const offset = nibbleAtBitOffset(bytes_be, bit_start + (chunk_i * 4));
        if (offset == 0) continue;
        const point = table[(chunk_i * 15) + (offset - 1)];
        acc.* = acc.*.addMixed(point);
    }
}

fn nibbleAtBitOffset(bytes_be: [32]u8, bit_offset: usize) usize {
    var out: usize = 0;
    var i: usize = 0;
    while (i < 4) : (i += 1) {
        const bit_index = bit_offset + i;
        const byte_from_lsb = bit_index / 8;
        const bit_in_byte = bit_index % 8;
        const byte = bytes_be[31 - byte_from_lsb];
        if (((byte >> @intCast(bit_in_byte)) & 1) == 1) {
            out |= (@as(usize, 1) << @intCast(i));
        }
    }
    return out;
}
