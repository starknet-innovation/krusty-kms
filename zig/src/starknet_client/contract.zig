const std = @import("std");
const core = @import("../core/root.zig");
const types = @import("types.zig");
const serialization = @import("serialization.zig");

pub const Error = error{
    InvalidResponse,
    InvalidPoint,
    InvalidInput,
};

pub fn decodeAccountState(response: []const core.Felt) Error!types.AccountState {
    if (response.len < 9) return Error.InvalidResponse;

    const balance_l = serialization.deserializeProjectivePoint(response[0], response[1]) catch {
        return Error.InvalidPoint;
    };
    const balance_r = serialization.deserializeProjectivePoint(response[2], response[3]) catch {
        return Error.InvalidPoint;
    };
    const pending_l = serialization.deserializeProjectivePoint(response[4], response[5]) catch {
        return Error.InvalidPoint;
    };
    const pending_r = serialization.deserializeProjectivePoint(response[6], response[7]) catch {
        return Error.InvalidPoint;
    };

    return .{
        .balance = .{
            .l = balance_l,
            .r = balance_r,
        },
        .pending = .{
            .l = pending_l,
            .r = pending_r,
        },
        .nonce = response[8],
    };
}

pub fn decodeRate(response: []const core.Felt) Error!u128 {
    if (response.len == 0) return Error.InvalidResponse;
    return serialization.u256ToU128(response[0], core.Felt.ZERO) catch Error.InvalidInput;
}

pub fn decodeBitSize(response: []const core.Felt) Error!u32 {
    if (response.len == 0) return Error.InvalidResponse;
    const value = response[0].toInt();
    if (value > std.math.maxInt(u32)) return Error.InvalidInput;
    return @intCast(value);
}

pub fn decodeErc20(response: []const core.Felt) Error!core.Felt {
    if (response.len == 0) return Error.InvalidResponse;
    return response[0];
}

pub fn decodeAuditorKey(response: []const core.Felt) Error!?core.ProjectivePoint {
    if (response.len == 0) return Error.InvalidResponse;
    if (core.Felt.eql(response[0], core.Felt.ONE)) return null;
    if (!core.Felt.eql(response[0], core.Felt.ZERO)) return Error.InvalidResponse;
    if (response.len < 3) return Error.InvalidResponse;

    return serialization.deserializeProjectivePoint(response[1], response[2]) catch Error.InvalidPoint;
}
