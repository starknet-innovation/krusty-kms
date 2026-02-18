const std = @import("std");
const core = @import("../core/root.zig");

/// Starknet selector = keccak256(name) masked to 250 bits.
pub fn selectorFromName(name: []const u8) core.Felt {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(name, &digest, .{});
    digest[0] &= 0x03; // keep lower 250 bits
    return core.Felt.fromBytesBeUnchecked(digest);
}

