const std = @import("std");
const core = @import("../core/root.zig");
const bip44 = @import("../kms/bip44.zig");
const mnemonic = @import("../kms/mnemonic.zig");
const derivation = @import("../kms/derivation.zig");
const account = @import("../kms/account.zig");
const crypto = @import("../crypto/root.zig");
const ffi_types = @import("types.zig");
const errors = @import("errors.zig");

const KmsFelt = ffi_types.KmsFelt;
const KmsProjectivePoint = ffi_types.KmsProjectivePoint;
const KmsAffinePoint = ffi_types.KmsAffinePoint;
const KmsTongoKeyPair = ffi_types.KmsTongoKeyPair;
const KmsNostrKeyPair = ffi_types.KmsNostrKeyPair;

const VERSION = "ghoul-kms-zig/0.1.0";

fn writeCString(src: []const u8, out: ?[*]u8, out_len: usize, out_written: ?*usize) errors.Code {
    if (out_written) |w| w.* = src.len;

    if (out == null) return .ok;

    // Require room for NUL terminator.
    if (out_len <= src.len) return .buffer_too_small;

    const out_slice = out.?[0..out_len];
    std.mem.copyForwards(u8, out_slice[0..src.len], src);
    out_slice[src.len] = 0;
    return .ok;
}

fn copyBytes(src: []const u8, out: ?[*]u8, out_len: usize, out_written: ?*usize) errors.Code {
    if (out_written) |w| w.* = src.len;
    if (out == null) return .ok;
    if (out_len < src.len) return .buffer_too_small;
    const out_slice = out.?[0..out_len];
    std.mem.copyForwards(u8, out_slice[0..src.len], src);
    return .ok;
}

fn cStringOrEmpty(value: ?[*:0]const u8) []const u8 {
    if (value == null) return "";
    return std.mem.span(value.?);
}

fn encodeHexNibble(n: u8) u8 {
    return if (n < 10) '0' + n else 'a' + (n - 10);
}

fn encodeFeltHex(bytes: [32]u8) [66]u8 {
    var out: [66]u8 = undefined;
    out[0] = '0';
    out[1] = 'x';

    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const b = bytes[i];
        out[2 + (2 * i)] = encodeHexNibble((b >> 4) & 0x0f);
        out[3 + (2 * i)] = encodeHexNibble(b & 0x0f);
    }

    return out;
}

pub export fn kms_get_abi_version(major: ?*u32, minor: ?*u32) callconv(.c) i32 {
    if (major == null or minor == null) return @intFromEnum(errors.Code.internal);
    major.?.* = 1;
    minor.?.* = 0;
    return @intFromEnum(errors.Code.ok);
}

pub export fn kms_get_version_string(out: ?[*]u8, out_len: usize, out_written: ?*usize) callconv(.c) i32 {
    return @intFromEnum(writeCString(VERSION, out, out_len, out_written));
}

pub export fn kms_felt_from_hex(hex: ?[*:0]const u8, out: ?*KmsFelt) callconv(.c) i32 {
    if (hex == null or out == null) return @intFromEnum(errors.Code.internal);

    const value = core.Felt.fromHex(std.mem.span(hex.?)) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };

    out.?.* = ffi_types.fromFelt(value);
    return @intFromEnum(errors.Code.ok);
}

pub export fn kms_felt_to_hex(value: ?*const KmsFelt, out: ?[*]u8, out_len: usize, out_written: ?*usize) callconv(.c) i32 {
    if (value == null) return @intFromEnum(errors.Code.internal);

    const felt = ffi_types.toFeltResult(value.?.*) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };

    const buf = encodeFeltHex(felt.toBytesBe());
    return @intFromEnum(writeCString(&buf, out, out_len, out_written));
}

pub export fn kms_felt_from_bytes_be(bytes: ?[*]const u8, bytes_len: usize, out: ?*KmsFelt) callconv(.c) i32 {
    if (bytes == null or out == null) return @intFromEnum(errors.Code.internal);

    const felt = core.Felt.fromBytesBeSlice(bytes.?[0..bytes_len]) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };

    out.?.* = ffi_types.fromFelt(felt);
    return @intFromEnum(errors.Code.ok);
}

pub export fn kms_felt_to_bytes_be(value: ?*const KmsFelt, out: ?[*]u8, out_len: usize, out_written: ?*usize) callconv(.c) i32 {
    if (value == null) return @intFromEnum(errors.Code.internal);

    const felt = ffi_types.toFeltResult(value.?.*) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };

    const b = felt.toBytesBe();
    return @intFromEnum(copyBytes(&b, out, out_len, out_written));
}

pub export fn kms_projective_from_affine(affine: ?*const KmsAffinePoint, out: ?*KmsProjectivePoint) callconv(.c) i32 {
    if (affine == null or out == null) return @intFromEnum(errors.Code.internal);

    const p = ffi_types.toAffine(affine.?.*);
    const proj = core.ProjectivePoint.fromAffine(p.x, p.y);
    out.?.* = ffi_types.fromProjective(proj);
    return @intFromEnum(errors.Code.ok);
}

pub export fn kms_projective_to_affine(point: ?*const KmsProjectivePoint, out: ?*KmsAffinePoint) callconv(.c) i32 {
    if (point == null or out == null) return @intFromEnum(errors.Code.internal);

    const p = ffi_types.toProjective(point.?.*);

    const affine = p.toAffine() orelse return @intFromEnum(errors.Code.point_at_infinity);

    out.?.* = ffi_types.fromAffine(affine);
    return @intFromEnum(errors.Code.ok);
}

pub export fn kms_pedersen_hash(left: ?*const KmsFelt, right: ?*const KmsFelt, out: ?*KmsFelt) callconv(.c) i32 {
    if (left == null or right == null or out == null) return @intFromEnum(errors.Code.internal);

    const l = ffi_types.toFeltResult(left.?.*) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };
    const r = ffi_types.toFeltResult(right.?.*) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };

    const hashed = crypto.pedersen.hash(l, r) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };

    out.?.* = ffi_types.fromFelt(hashed);
    return @intFromEnum(errors.Code.ok);
}

pub export fn kms_poseidon_hash_many(values: ?[*]const KmsFelt, values_len: usize, out: ?*KmsFelt) callconv(.c) i32 {
    if (out == null) return @intFromEnum(errors.Code.internal);
    if (values_len > 0 and values == null) return @intFromEnum(errors.Code.internal);

    var tmp: std.ArrayList(core.Felt) = .empty;
    defer tmp.deinit(std.heap.page_allocator);

    var i: usize = 0;
    while (i < values_len) : (i += 1) {
        const v = ffi_types.toFeltResult(values.?[i]) catch |err| {
            return @intFromEnum(errors.mapAny(err));
        };
        tmp.append(std.heap.page_allocator, v) catch return @intFromEnum(errors.Code.internal);
    }

    const hashed = crypto.poseidon.hashMany(tmp.items) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };

    out.?.* = ffi_types.fromFelt(hashed);
    return @intFromEnum(errors.Code.ok);
}

pub export fn kms_generate_mnemonic(word_count: u32, out: ?[*]u8, out_len: usize, out_written: ?*usize) callconv(.c) i32 {
    var tmp = [_]u8{0} ** 256;
    const phrase = mnemonic.generateMnemonic(word_count, &tmp) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };
    return @intFromEnum(writeCString(phrase, out, out_len, out_written));
}

pub export fn kms_generate_mnemonic_from_entropy(entropy: ?[*]const u8, entropy_len: usize, out: ?[*]u8, out_len: usize, out_written: ?*usize) callconv(.c) i32 {
    if (entropy == null) return @intFromEnum(errors.Code.internal);

    var tmp = [_]u8{0} ** 256;
    const phrase = mnemonic.generateMnemonicFromEntropy(entropy.?[0..entropy_len], &tmp) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };
    return @intFromEnum(writeCString(phrase, out, out_len, out_written));
}

pub export fn kms_validate_mnemonic(phrase: ?[*:0]const u8) callconv(.c) i32 {
    if (phrase == null) return @intFromEnum(errors.Code.internal);
    mnemonic.validateMnemonic(std.mem.span(phrase.?)) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };
    return @intFromEnum(errors.Code.ok);
}

pub export fn kms_mnemonic_to_seed(phrase: ?[*:0]const u8, passphrase: ?[*:0]const u8, out: ?[*]u8, out_len: usize, out_written: ?*usize) callconv(.c) i32 {
    if (phrase == null) return @intFromEnum(errors.Code.internal);

    const seed = mnemonic.mnemonicToSeed(std.mem.span(phrase.?), cStringOrEmpty(passphrase)) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };
    return @intFromEnum(copyBytes(&seed, out, out_len, out_written));
}

pub export fn kms_derive_private_key_with_coin_type(mnemonic_phrase: ?[*:0]const u8, index: u32, account_index: u32, coin_type: u32, passphrase: ?[*:0]const u8, out: ?*KmsFelt) callconv(.c) i32 {
    if (mnemonic_phrase == null or out == null) return @intFromEnum(errors.Code.internal);

    const private_key = derivation.derivePrivateKeyWithCoinType(
        std.mem.span(mnemonic_phrase.?),
        index,
        account_index,
        coin_type,
        cStringOrEmpty(passphrase),
    ) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };

    out.?.* = ffi_types.fromFelt(private_key);
    return @intFromEnum(errors.Code.ok);
}

pub export fn kms_derive_keypair_with_coin_type(mnemonic_phrase: ?[*:0]const u8, index: u32, account_index: u32, coin_type: u32, passphrase: ?[*:0]const u8, out: ?*KmsTongoKeyPair) callconv(.c) i32 {
    if (mnemonic_phrase == null or out == null) return @intFromEnum(errors.Code.internal);

    const keypair = derivation.deriveKeypairWithCoinType(
        std.mem.span(mnemonic_phrase.?),
        index,
        account_index,
        coin_type,
        cStringOrEmpty(passphrase),
    ) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };

    out.?.* = .{
        .private_key = ffi_types.fromFelt(keypair.private_key),
        .public_key = ffi_types.fromProjective(keypair.public_key),
    };
    return @intFromEnum(errors.Code.ok);
}

pub export fn kms_derive_view_private_key(mnemonic_phrase: ?[*:0]const u8, index: u32, account_index: u32, passphrase: ?[*:0]const u8, out: ?*KmsFelt) callconv(.c) i32 {
    if (mnemonic_phrase == null or out == null) return @intFromEnum(errors.Code.internal);

    const private_key = derivation.deriveViewPrivateKey(
        std.mem.span(mnemonic_phrase.?),
        index,
        account_index,
        cStringOrEmpty(passphrase),
    ) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };

    out.?.* = ffi_types.fromFelt(private_key);
    return @intFromEnum(errors.Code.ok);
}

pub export fn kms_derive_view_keypair(mnemonic_phrase: ?[*:0]const u8, index: u32, account_index: u32, passphrase: ?[*:0]const u8, out: ?*KmsTongoKeyPair) callconv(.c) i32 {
    if (mnemonic_phrase == null or out == null) return @intFromEnum(errors.Code.internal);

    const keypair = derivation.deriveViewKeypair(
        std.mem.span(mnemonic_phrase.?),
        index,
        account_index,
        cStringOrEmpty(passphrase),
    ) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };

    out.?.* = .{
        .private_key = ffi_types.fromFelt(keypair.private_key),
        .public_key = ffi_types.fromProjective(keypair.public_key),
    };
    return @intFromEnum(errors.Code.ok);
}

pub export fn kms_derive_nostr_private_key(mnemonic_phrase: ?[*:0]const u8, index: u32, account_index: u32, passphrase: ?[*:0]const u8, out: ?[*]u8) callconv(.c) i32 {
    if (mnemonic_phrase == null or out == null) return @intFromEnum(errors.Code.internal);

    const key = derivation.deriveNostrPrivateKey(
        std.mem.span(mnemonic_phrase.?),
        index,
        account_index,
        cStringOrEmpty(passphrase),
    ) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };

    std.mem.copyForwards(u8, out.?[0..32], &key);
    return @intFromEnum(errors.Code.ok);
}

pub export fn kms_derive_nostr_keypair(mnemonic_phrase: ?[*:0]const u8, index: u32, account_index: u32, passphrase: ?[*:0]const u8, out: ?*KmsNostrKeyPair) callconv(.c) i32 {
    if (mnemonic_phrase == null or out == null) return @intFromEnum(errors.Code.internal);

    const keypair = derivation.deriveNostrKeypair(
        std.mem.span(mnemonic_phrase.?),
        index,
        account_index,
        cStringOrEmpty(passphrase),
    ) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };

    out.?.* = .{
        .private_key = keypair.private_key,
        .public_key_xonly = keypair.public_key_xonly,
    };
    return @intFromEnum(errors.Code.ok);
}

pub export fn kms_calculate_contract_address(salt: ?*const KmsFelt, class_hash: ?*const KmsFelt, constructor_calldata: ?[*]const KmsFelt, constructor_calldata_len: usize, deployer_address: ?*const KmsFelt, out: ?*KmsFelt) callconv(.c) i32 {
    if (salt == null or class_hash == null or deployer_address == null or out == null) {
        return @intFromEnum(errors.Code.internal);
    }
    if (constructor_calldata_len > 0 and constructor_calldata == null) {
        return @intFromEnum(errors.Code.internal);
    }

    var list: std.ArrayList(core.Felt) = .empty;
    defer list.deinit(std.heap.page_allocator);

    var i: usize = 0;
    while (i < constructor_calldata_len) : (i += 1) {
        const felt = ffi_types.toFeltResult(constructor_calldata.?[i]) catch |err| {
            return @intFromEnum(errors.mapAny(err));
        };
        list.append(std.heap.page_allocator, felt) catch return @intFromEnum(errors.Code.internal);
    }

    const result = account.calculateContractAddress(
        ffi_types.toFeltResult(salt.?.*) catch |err| {
            return @intFromEnum(errors.mapAny(err));
        },
        ffi_types.toFeltResult(class_hash.?.*) catch |err| {
            return @intFromEnum(errors.mapAny(err));
        },
        list.items,
        ffi_types.toFeltResult(deployer_address.?.*) catch |err| {
            return @intFromEnum(errors.mapAny(err));
        },
    ) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };

    out.?.* = ffi_types.fromFelt(result);
    return @intFromEnum(errors.Code.ok);
}

pub export fn kms_derive_oz_account_address(public_key_x: ?*const KmsFelt, class_hash: ?*const KmsFelt, salt: ?*const KmsFelt, out: ?*KmsFelt) callconv(.c) i32 {
    if (public_key_x == null or class_hash == null or out == null) return @intFromEnum(errors.Code.internal);

    const public_x = ffi_types.toFeltResult(public_key_x.?.*) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };
    const cls_hash = ffi_types.toFeltResult(class_hash.?.*) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };
    const salt_felt = if (salt) |s|
        ffi_types.toFeltResult(s.*) catch |err| {
            return @intFromEnum(errors.mapAny(err));
        }
    else
        null;

    const address = account.deriveOzAccountAddress(public_x, cls_hash, salt_felt) catch |err| {
        return @intFromEnum(errors.mapAny(err));
    };
    out.?.* = ffi_types.fromFelt(address);
    return @intFromEnum(errors.Code.ok);
}

pub export fn kms_get_coin_type_tongo() callconv(.c) u32 {
    return bip44.TONGO_COIN_TYPE;
}

pub export fn kms_get_coin_type_starknet() callconv(.c) u32 {
    return bip44.STARKNET_COIN_TYPE;
}

pub export fn kms_get_coin_type_tongo_view() callconv(.c) u32 {
    return bip44.TONGO_VIEW_COIN_TYPE;
}

pub export fn kms_get_coin_type_nostr() callconv(.c) u32 {
    return bip44.NOSTR_COIN_TYPE;
}

pub export fn kms_error_name(code: i32) callconv(.c) [*:0]const u8 {
    return errors.name(@intFromEnum(errors.fromInt(code)));
}

pub export fn kms_error_message(code: i32) callconv(.c) [*:0]const u8 {
    return errors.message(@intFromEnum(errors.fromInt(code)));
}
