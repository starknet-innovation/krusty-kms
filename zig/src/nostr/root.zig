const std = @import("std");
const she_rng = @import("../she/rng.zig");

pub const VERSION: u8 = 2;

pub const Error = error{
    InvalidHex,
    InvalidKey,
    InvalidPayload,
    MacMismatch,
    CryptoFailure,
    OutOfMemory,
};

pub fn deriveSharedSecret(
    sender_sk_hex: []const u8,
    receiver_pk_hex: []const u8,
) Error![32]u8 {
    const sk = try decodeSecretKey(sender_sk_hex);
    const pk = try decodePublicKey(receiver_pk_hex);
    const shared = pk.mul(sk, .big) catch return Error.InvalidKey;
    const affine = shared.affineCoordinates();
    return affine.x.toBytes(.big);
}

pub fn derivePublicKey(
    allocator: std.mem.Allocator,
    secret_hex: []const u8,
) Error![]u8 {
    const sk = try decodeSecretKey(secret_hex);
    const pk = std.crypto.ecc.Secp256k1.basePoint.mul(sk, .big) catch return Error.InvalidKey;
    const sec1 = pk.toCompressedSec1();
    return bytesToHex(allocator, &sec1);
}

pub fn encryptMessage(
    allocator: std.mem.Allocator,
    sender_sk_hex: []const u8,
    receiver_pk_hex: []const u8,
    plaintext: []const u8,
) Error![]u8 {
    const shared = try deriveSharedSecret(sender_sk_hex, receiver_pk_hex);
    const keys = deriveKeys(shared);

    var nonce: [12]u8 = undefined;
    she_rng.fillBytes(&nonce);

    const ciphertext = allocator.alloc(u8, plaintext.len) catch return Error.OutOfMemory;
    defer allocator.free(ciphertext);
    @memcpy(ciphertext, plaintext);
    std.crypto.stream.chacha.ChaCha20IETF.xor(
        ciphertext,
        ciphertext,
        0,
        keys.enc_key,
        nonce,
    );

    const mac = computeMac(keys.mac_key, VERSION, nonce, ciphertext);

    const total_len = 1 + nonce.len + ciphertext.len + mac.len;
    const payload = allocator.alloc(u8, total_len) catch return Error.OutOfMemory;
    defer allocator.free(payload);

    payload[0] = VERSION;
    @memcpy(payload[1..13], &nonce);
    @memcpy(payload[13 .. 13 + ciphertext.len], ciphertext);
    @memcpy(payload[13 + ciphertext.len ..], &mac);

    const encoded_len = std.base64.standard.Encoder.calcSize(payload.len);
    const encoded = allocator.alloc(u8, encoded_len) catch return Error.OutOfMemory;
    _ = std.base64.standard.Encoder.encode(encoded, payload);
    return encoded;
}

pub fn decryptMessage(
    allocator: std.mem.Allocator,
    receiver_sk_hex: []const u8,
    sender_pk_hex: []const u8,
    payload_b64: []const u8,
) Error![]u8 {
    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(payload_b64) catch {
        return Error.InvalidPayload;
    };
    const decoded = allocator.alloc(u8, decoded_len) catch return Error.OutOfMemory;
    defer allocator.free(decoded);
    std.base64.standard.Decoder.decode(decoded, payload_b64) catch {
        return Error.InvalidPayload;
    };
    const data = decoded;

    if (data.len < 1 + 12 + 32) return Error.InvalidPayload;
    if (data[0] != VERSION) return Error.InvalidPayload;

    const nonce: [12]u8 = data[1..13].*;
    const mac_start = data.len - 32;
    const ciphertext = data[13..mac_start];
    var mac_bytes: [32]u8 = undefined;
    @memcpy(&mac_bytes, data[mac_start..][0..32]);

    const shared = try deriveSharedSecret(receiver_sk_hex, sender_pk_hex);
    const keys = deriveKeys(shared);
    const expected_mac = computeMac(keys.mac_key, VERSION, nonce, ciphertext);
    if (!std.crypto.timing_safe.eql([32]u8, expected_mac, mac_bytes)) {
        return Error.MacMismatch;
    }

    const plaintext = allocator.alloc(u8, ciphertext.len) catch return Error.OutOfMemory;
    @memcpy(plaintext, ciphertext);
    std.crypto.stream.chacha.ChaCha20IETF.xor(
        plaintext,
        plaintext,
        0,
        keys.enc_key,
        nonce,
    );
    return plaintext;
}

const DerivedKeys = struct {
    enc_key: [32]u8,
    mac_key: [32]u8,
};

fn deriveKeys(shared: [32]u8) DerivedKeys {
    const hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const prk = hkdf.extract("", &shared);
    var okm: [64]u8 = undefined;
    hkdf.expand(&okm, "nostr-nip44-v2", prk);

    var enc: [32]u8 = undefined;
    var mac: [32]u8 = undefined;
    @memcpy(&enc, okm[0..32]);
    @memcpy(&mac, okm[32..64]);
    return .{
        .enc_key = enc,
        .mac_key = mac,
    };
}

fn computeMac(
    mac_key: [32]u8,
    version: u8,
    nonce: [12]u8,
    ciphertext: []const u8,
) [32]u8 {
    var out: [32]u8 = undefined;
    var ctx = std.crypto.auth.hmac.sha2.HmacSha256.init(&mac_key);
    ctx.update(&[_]u8{version});
    ctx.update(&nonce);
    ctx.update(ciphertext);
    ctx.final(&out);
    return out;
}

fn decodeSecretKey(hex_str: []const u8) Error![32]u8 {
    const bytes = try decodeHexExact(hex_str, 32);
    if (std.mem.allEqual(u8, &bytes, 0)) return Error.InvalidKey;
    std.crypto.ecc.Secp256k1.scalar.rejectNonCanonical(bytes, .big) catch {
        return Error.InvalidKey;
    };
    return bytes;
}

fn decodePublicKey(hex_str: []const u8) Error!std.crypto.ecc.Secp256k1 {
    const raw = strip0x(hex_str);
    if (raw.len == 0 or raw.len % 2 != 0 or raw.len > 130) return Error.InvalidKey;

    var buf: [65]u8 = undefined;
    const decoded = decodeHexInto(raw, buf[0 .. raw.len / 2]) catch return Error.InvalidKey;
    return std.crypto.ecc.Secp256k1.fromSec1(decoded) catch Error.InvalidKey;
}

fn decodeHexExact(input: []const u8, expected_len: usize) Error![32]u8 {
    var out: [32]u8 = undefined;
    const raw = strip0x(input);
    if (raw.len != expected_len * 2) return Error.InvalidHex;

    var i: usize = 0;
    while (i < expected_len) : (i += 1) {
        const hi = hexNibble(raw[i * 2]) catch return Error.InvalidHex;
        const lo = hexNibble(raw[i * 2 + 1]) catch return Error.InvalidHex;
        out[i] = (hi << 4) | lo;
    }
    return out;
}

fn decodeHexInto(raw: []const u8, out: []u8) error{InvalidHex}![]u8 {
    if (raw.len != out.len * 2) return error.InvalidHex;
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        const hi = try hexNibble(raw[i * 2]);
        const lo = try hexNibble(raw[i * 2 + 1]);
        out[i] = (hi << 4) | lo;
    }
    return out;
}

fn bytesToHex(allocator: std.mem.Allocator, data: []const u8) Error![]u8 {
    const out = allocator.alloc(u8, data.len * 2) catch return Error.OutOfMemory;
    var i: usize = 0;
    while (i < data.len) : (i += 1) {
        const b = data[i];
        out[i * 2] = nibbleToHex((b >> 4) & 0x0f);
        out[i * 2 + 1] = nibbleToHex(b & 0x0f);
    }
    return out;
}

fn strip0x(s: []const u8) []const u8 {
    if (std.mem.startsWith(u8, s, "0x") or std.mem.startsWith(u8, s, "0X")) {
        return s[2..];
    }
    return s;
}

fn hexNibble(c: u8) error{InvalidHex}!u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidHex,
    };
}

fn nibbleToHex(n: u8) u8 {
    return if (n < 10) ('0' + n) else ('a' + (n - 10));
}
