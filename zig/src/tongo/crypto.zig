const std = @import("std");
const core = @import("../core/root.zig");
const she = @import("../she/root.zig");
const she_rng = @import("../she/rng.zig");

pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;

pub const AuditHint = struct {
    ciphertext: [64]u8,
    nonce: [24]u8,
};

pub const Error = error{
    PointAtInfinity,
    CryptoFailure,
};

pub fn deriveSharedSecret(
    my_private_key: core.Felt,
    other_public_key: core.ProjectivePoint,
) Error![32]u8 {
    const shared_point = she.curve.mul(my_private_key, other_public_key);
    const affine = shared_point.toAffine() orelse return Error.PointAtInfinity;

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("TONGO_AUDIT_KEY_V1");
    const x_bytes = affine.x.toBytesBe();
    hasher.update(&x_bytes);

    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

pub fn encryptAuditHint(
    plaintext_balance: u128,
    shared_secret: [32]u8,
) AuditHint {
    var nonce: [NONCE_SIZE]u8 = undefined;
    she_rng.fillBytes(&nonce);

    var plaintext: [16]u8 = undefined;
    std.mem.writeInt(u128, &plaintext, plaintext_balance, .big);

    var encrypted: [16]u8 = undefined;
    var tag: [TAG_SIZE]u8 = undefined;
    std.crypto.aead.chacha_poly.XChaCha20Poly1305.encrypt(
        &encrypted,
        &tag,
        &plaintext,
        &.{},
        nonce,
        shared_secret,
    );

    var ciphertext: [64]u8 = [_]u8{0} ** 64;
    std.mem.copyForwards(u8, ciphertext[0..16], &encrypted);
    std.mem.copyForwards(u8, ciphertext[16..32], &tag);

    return .{
        .ciphertext = ciphertext,
        .nonce = nonce,
    };
}

pub fn decryptAuditHint(
    ciphertext: [64]u8,
    nonce: [24]u8,
    shared_secret: [32]u8,
) Error!u128 {
    const tag: [TAG_SIZE]u8 = ciphertext[16..32].*;
    var out: [16]u8 = undefined;

    std.crypto.aead.chacha_poly.XChaCha20Poly1305.decrypt(
        &out,
        ciphertext[0..16],
        tag,
        &.{},
        nonce,
        shared_secret,
    ) catch return Error.CryptoFailure;

    return std.mem.readInt(u128, &out, .big);
}

pub fn encryptForAuditor(
    balance: u128,
    user_private_key: core.Felt,
    auditor_public_key: core.ProjectivePoint,
) Error!AuditHint {
    const shared_secret = try deriveSharedSecret(user_private_key, auditor_public_key);
    return encryptAuditHint(balance, shared_secret);
}

pub fn decryptAsAuditor(
    ciphertext: [64]u8,
    nonce: [24]u8,
    auditor_private_key: core.Felt,
    user_public_key: core.ProjectivePoint,
) Error!u128 {
    const shared_secret = try deriveSharedSecret(auditor_private_key, user_public_key);
    return decryptAuditHint(ciphertext, nonce, shared_secret);
}
