const std = @import("std");
const U256 = @import("u256.zig").U256;
const fp = @import("field/stark_fp.zig");

pub const Error = error{
    InvalidHex,
    Overflow,
    NotInField,
    InvalidLength,
    DivisionByZero,
    Unsupported,
};

// Stark field modulus:
// 2^251 + 17*2^192 + 1
const MODULUS = fp.MODULUS;
pub const MODULUS_INT: u256 = fp.MODULUS_INT;
const MODULUS_MINUS_TWO: u256 = MODULUS_INT - 2;

pub const Felt = struct {
    raw: U256,

    pub const ZERO = Felt{ .raw = U256.zero() };
    pub const ONE = Felt{ .raw = U256.fromU64(1) };
    pub const TWO = Felt{ .raw = U256.fromU64(2) };

    pub fn fromU64(v: u64) Felt {
        return .{ .raw = U256.fromU64(v) };
    }

    pub fn fromInt(v: u256) Error!Felt {
        return fromU256(U256.fromInt(v));
    }

    pub fn fromHex(input: []const u8) Error!Felt {
        const value = U256.fromHex(input) catch |err| switch (err) {
            error.InvalidHex => return Error.InvalidHex,
            error.Overflow => return Error.Overflow,
        };
        return fromU256(value);
    }

    pub fn fromBytesBe(bytes: [32]u8) Error!Felt {
        return fromU256(U256.fromBytesBe(bytes));
    }

    pub fn fromBytesBeSlice(bytes: []const u8) Error!Felt {
        if (bytes.len == 0) return Error.InvalidLength;
        if (bytes.len > 32) return Error.Overflow;

        var padded = [_]u8{0} ** 32;
        std.mem.copyForwards(u8, padded[32 - bytes.len ..], bytes);
        return fromBytesBe(padded);
    }

    pub fn fromDecStr(_: []const u8) Error!Felt {
        return Error.Unsupported;
    }

    pub fn toBytesBe(self: Felt) [32]u8 {
        return self.raw.toBytesBe();
    }

    pub fn toInt(self: Felt) u256 {
        return self.raw.toInt();
    }

    pub fn eql(a: Felt, b: Felt) bool {
        return U256.eql(a.raw, b.raw);
    }

    pub fn isZero(self: Felt) bool {
        return eql(self, ZERO);
    }

    pub fn add(a: Felt, b: Felt) Felt {
        return .{ .raw = U256.fromInt(fp.addCanonical(a.toInt(), b.toInt())) };
    }

    pub fn sub(a: Felt, b: Felt) Felt {
        return .{ .raw = U256.fromInt(fp.subCanonical(a.toInt(), b.toInt())) };
    }

    pub fn mul(a: Felt, b: Felt) Felt {
        return .{ .raw = U256.fromInt(fp.mulCanonical(a.toInt(), b.toInt())) };
    }

    pub fn square(a: Felt) Felt {
        return .{ .raw = U256.fromInt(fp.squareCanonical(a.toInt())) };
    }

    pub fn neg(a: Felt) Felt {
        if (a.isZero()) return ZERO;
        return .{ .raw = U256.fromInt(MODULUS_INT - a.toInt()) };
    }

    pub fn pow(base: Felt, exponent: u256) Felt {
        var result = ONE;
        var acc = base;
        var e = exponent;

        while (e != 0) : (e >>= 1) {
            if ((e & 1) == 1) {
                result = result.mul(acc);
            }
            acc = acc.square();
        }

        return result;
    }

    pub fn inverse(a: Felt) Error!Felt {
        if (a.isZero()) return Error.DivisionByZero;
        // Fermat's little theorem over prime field: a^(p-2) mod p
        return pow(a, MODULUS_MINUS_TWO);
    }

    pub fn div(a: Felt, b: Felt) Error!Felt {
        const inv = try b.inverse();
        return a.mul(inv);
    }

    pub fn toBitsLe(self: Felt) [256]bool {
        var bits = [_]bool{false} ** 256;
        const bytes = self.toBytesBe();
        var byte_i: usize = 0;
        while (byte_i < 32) : (byte_i += 1) {
            const b = bytes[31 - byte_i];
            var bit_i: usize = 0;
            while (bit_i < 8) : (bit_i += 1) {
                bits[(byte_i * 8) + bit_i] = ((b >> @intCast(bit_i)) & 1) == 1;
            }
        }
        return bits;
    }

    pub fn fromBytesBeUnchecked(bytes: [32]u8) Felt {
        const v = U256.fromBytesBe(bytes).toInt() % MODULUS_INT;
        return .{ .raw = U256.fromInt(v) };
    }

    pub fn format(
        self: Felt,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try self.raw.format("", .{}, writer);
    }
};

fn fromU256(value: U256) Error!Felt {
    if (!U256.lt(value, MODULUS)) return Error.NotInField;
    return .{ .raw = value };
}
