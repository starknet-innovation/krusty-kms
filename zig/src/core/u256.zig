const std = @import("std");

pub const Error = error{
    InvalidHex,
    Overflow,
};

pub const U256 = struct {
    value: u256,

    pub fn zero() U256 {
        return .{ .value = 0 };
    }

    pub fn fromU64(value: u64) U256 {
        return .{ .value = @as(u256, value) };
    }

    pub fn fromInt(value: u256) U256 {
        return .{ .value = value };
    }

    pub fn toInt(self: U256) u256 {
        return self.value;
    }

    pub fn fromBytesBe(bytes: [32]u8) U256 {
        return .{ .value = std.mem.readInt(u256, &bytes, .big) };
    }

    pub fn toBytesBe(self: U256) [32]u8 {
        var out: [32]u8 = undefined;
        std.mem.writeInt(u256, &out, self.value, .big);
        return out;
    }

    pub fn eql(a: U256, b: U256) bool {
        return a.value == b.value;
    }

    pub fn lt(a: U256, b: U256) bool {
        return a.value < b.value;
    }

    pub fn fromHex(input: []const u8) Error!U256 {
        @setEvalBranchQuota(20_000_000);
        var s = input;
        if (std.mem.startsWith(u8, s, "0x") or std.mem.startsWith(u8, s, "0X")) {
            s = s[2..];
        }

        if (s.len == 0) return Error.InvalidHex;
        if (s.len > 64) return Error.Overflow;

        var value: u256 = 0;
        for (s) |c| {
            const nib = try parseHexNibble(c);
            const shifted, const overflow = @shlWithOverflow(value, 4);
            if (overflow != 0) return Error.Overflow;
            value = shifted | @as(u256, nib);
        }

        return .{ .value = value };
    }

    pub fn add(a: U256, b: U256) struct { sum: U256, carry: bool } {
        const sum, const carry = @addWithOverflow(a.value, b.value);
        return .{ .sum = fromInt(sum), .carry = carry != 0 };
    }

    pub fn sub(a: U256, b: U256) struct { diff: U256, borrow: bool } {
        const diff, const borrow = @subWithOverflow(a.value, b.value);
        return .{ .diff = fromInt(diff), .borrow = borrow != 0 };
    }

    pub fn format(
        self: U256,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.writeAll("0x");
        for (self.toBytesBe()) |b| {
            try writer.print("{x:0>2}", .{b});
        }
    }
};

fn parseHexNibble(c: u8) Error!u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => Error.InvalidHex,
    };
}
