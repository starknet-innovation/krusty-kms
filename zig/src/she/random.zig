const std = @import("std");
const core = @import("../core/root.zig");
const scalar = @import("scalar.zig");

pub fn randomFelt() core.Felt {
    return scalar.randomScalar();
}

pub fn randomFelts(allocator: std.mem.Allocator, count: usize) ![]core.Felt {
    const out = try allocator.alloc(core.Felt, count);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        out[i] = randomFelt();
    }
    return out;
}

