const std = @import("std");
const hash = @import("../crypto/hash.zig");

pub const Error = error{
    CryptoFailure,
};

pub const ExtendedPrivateKey = struct {
    key: [32]u8,
    chain_code: [32]u8,
};

const SECP256K1_ORDER = @import("../core/u256.zig").U256.fromHex(
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
) catch unreachable;
const SECP256K1_ORDER_INT: u256 = SECP256K1_ORDER.toInt();

pub fn deriveMasterKey(seed: []const u8) ExtendedPrivateKey {
    const i = hash.hmacSha512("Bitcoin seed", seed);
    var key: [32]u8 = undefined;
    var chain: [32]u8 = undefined;
    @memcpy(&key, i[0..32]);
    @memcpy(&chain, i[32..64]);
    return .{ .key = key, .chain_code = chain };
}

pub fn deriveChild(parent: ExtendedPrivateKey, index: u32) Error!ExtendedPrivateKey {
    var data: [37]u8 = undefined;
    const hardened = (index & 0x8000_0000) != 0;

    if (hardened) {
        data[0] = 0;
        @memcpy(data[1..33], &parent.key);
    } else {
        const compressed = try secpCompressedPublicKey(parent.key);
        @memcpy(data[0..33], &compressed);
    }
    const index_bytes = std.mem.toBytes(std.mem.nativeToBig(u32, index));
    @memcpy(data[33..37], &index_bytes);

    const i = hash.hmacSha512(&parent.chain_code, &data);

    var il: [32]u8 = undefined;
    var ir: [32]u8 = undefined;
    @memcpy(&il, i[0..32]);
    @memcpy(&ir, i[32..64]);

    const il_int = std.mem.readInt(u256, &il, .big);
    const parent_int = std.mem.readInt(u256, &parent.key, .big);
    const child_wide: u512 = @as(u512, il_int) + @as(u512, parent_int);
    const child_int: u256 = @intCast(child_wide % @as(u512, SECP256K1_ORDER_INT));

    var child_key: [32]u8 = undefined;
    std.mem.writeInt(u256, &child_key, child_int, .big);

    return .{
        .key = child_key,
        .chain_code = ir,
    };
}

pub fn derivePath(master: ExtendedPrivateKey, path: []const u32) Error!ExtendedPrivateKey {
    var node = master;
    for (path) |index| {
        node = try deriveChild(node, index);
    }
    return node;
}

pub fn secpCompressedPublicKey(private_key: [32]u8) Error![33]u8 {
    const point = std.crypto.ecc.Secp256k1.basePoint.mul(private_key, .big) catch {
        return Error.CryptoFailure;
    };
    return point.toCompressedSec1();
}

pub fn secpXOnlyPublicKey(private_key: [32]u8) Error![32]u8 {
    const point = std.crypto.ecc.Secp256k1.basePoint.mul(private_key, .big) catch {
        return Error.CryptoFailure;
    };
    const uncompressed = point.toUncompressedSec1();
    var xonly: [32]u8 = undefined;
    @memcpy(&xonly, uncompressed[1..33]);
    return xonly;
}
