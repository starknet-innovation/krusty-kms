const std = @import("std");

pub const Error = error{
    CryptoFailure,
};

pub fn sha256(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
    return out;
}

pub fn sha512(data: []const u8) [64]u8 {
    var out: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(data, &out, .{});
    return out;
}

pub fn hmacSha512(key: []const u8, data: []const u8) [64]u8 {
    var out: [64]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha512.create(&out, data, key);
    return out;
}

pub fn pbkdf2HmacSha512(password: []const u8, salt: []const u8, rounds: u32, out: []u8) Error!void {
    std.crypto.pwhash.pbkdf2(out, password, salt, rounds, std.crypto.auth.hmac.sha2.HmacSha512) catch {
        return Error.CryptoFailure;
    };
}
