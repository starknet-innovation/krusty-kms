const std = @import("std");

pub const Code = enum(i32) {
    ok = 0,
    invalid_hex = -1,
    invalid_length = -2,
    invalid_mnemonic = -3,
    invalid_derivation_path = -4,
    not_in_field = -5,
    point_at_infinity = -6,
    crypto_failure = -7,
    buffer_too_small = -8,
    unimplemented = -9,
    internal = -10,
};

pub fn mapAny(err: anyerror) Code {
    return switch (err) {
        error.InvalidHex => .invalid_hex,
        error.InvalidLength => .invalid_length,
        error.NotInField => .not_in_field,
        error.InvalidMnemonic => .invalid_mnemonic,
        error.CryptoFailure,
        error.DivisionByZero,
        => .crypto_failure,
        error.InvalidPath,
        error.InvalidSegment,
        error.HardenedForbidden,
        error.HardenedRequired,
        => .invalid_derivation_path,
        error.Unimplemented,
        error.Unsupported,
        => .unimplemented,
        error.OutOfMemory,
        error.NoSpaceLeft,
        => .buffer_too_small,
        else => .internal,
    };
}

pub fn name(code: i32) [*:0]const u8 {
    const c: Code = @enumFromInt(code);
    return switch (c) {
        .ok => "KMS_OK",
        .invalid_hex => "KMS_ERR_INVALID_HEX",
        .invalid_length => "KMS_ERR_INVALID_LENGTH",
        .invalid_mnemonic => "KMS_ERR_INVALID_MNEMONIC",
        .invalid_derivation_path => "KMS_ERR_INVALID_DERIVATION_PATH",
        .not_in_field => "KMS_ERR_NOT_IN_FIELD",
        .point_at_infinity => "KMS_ERR_POINT_AT_INFINITY",
        .crypto_failure => "KMS_ERR_CRYPTO_FAILURE",
        .buffer_too_small => "KMS_ERR_BUFFER_TOO_SMALL",
        .unimplemented => "KMS_ERR_UNIMPLEMENTED",
        .internal => "KMS_ERR_INTERNAL",
    };
}

pub fn message(code: i32) [*:0]const u8 {
    const c: Code = @enumFromInt(code);
    return switch (c) {
        .ok => "success",
        .invalid_hex => "invalid hex value",
        .invalid_length => "invalid input length",
        .invalid_mnemonic => "invalid mnemonic phrase",
        .invalid_derivation_path => "invalid derivation path",
        .not_in_field => "value is not a valid Stark field element",
        .point_at_infinity => "point at infinity",
        .crypto_failure => "cryptographic operation failed",
        .buffer_too_small => "output buffer too small",
        .unimplemented => "function is not implemented",
        .internal => "internal error",
    };
}

pub fn fromInt(code: i32) Code {
    return std.meta.intToEnum(Code, code) catch .internal;
}
