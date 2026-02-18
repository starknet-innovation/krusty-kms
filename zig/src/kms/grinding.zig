const std = @import("std");
const core = @import("../core/root.zig");
const hash = @import("../crypto/hash.zig");
const U256 = @import("../core/u256.zig").U256;

pub const Error = error{
    CryptoFailure,
};

const STARK_CURVE_ORDER = U256.fromHex(
    "0x0800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2f",
) catch unreachable;
const STARK_CURVE_ORDER_INT: u256 = STARK_CURVE_ORDER.toInt();

const TWO_256: u512 = @as(u512, 1) << 256;
const MAX_ALLOWED: u512 = TWO_256 - (TWO_256 % @as(u512, STARK_CURVE_ORDER_INT));

pub fn grindKey(seed: [32]u8) Error!core.Felt {
    var input: [33]u8 = undefined;
    @memcpy(input[0..32], &seed);

    var i: usize = 0;
    while (i < 256) : (i += 1) {
        input[32] = @intCast(i);
        const digest = hash.sha256(&input);
        const candidate = std.mem.readInt(u256, &digest, .big);
        if (@as(u512, candidate) < MAX_ALLOWED) {
            const reduced = candidate % STARK_CURVE_ORDER_INT;
            return core.Felt.fromInt(reduced) catch Error.CryptoFailure;
        }
    }

    return Error.CryptoFailure;
}
