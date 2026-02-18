const core = @import("../core/root.zig");
const crypto = @import("../crypto/root.zig");

pub const Error = error{
    CryptoFailure,
    InvalidLength,
};

const CONTRACT_ADDRESS_PREFIX = "STARKNET_CONTRACT_ADDRESS";

pub fn calculateContractAddress(
    salt: core.Felt,
    class_hash: core.Felt,
    constructor_calldata: []const core.Felt,
    deployer_address: core.Felt,
) Error!core.Felt {
    const calldata_hash = try hashElements(constructor_calldata);
    const prefix = try encodeShortString(CONTRACT_ADDRESS_PREFIX);

    var elements: [5]core.Felt = .{
        prefix,
        deployer_address,
        salt,
        class_hash,
        calldata_hash,
    };
    return hashElements(&elements);
}

pub fn deriveOzAccountAddress(
    public_key_x: core.Felt,
    class_hash: core.Felt,
    salt: ?core.Felt,
) Error!core.Felt {
    const effective_salt = salt orelse core.Felt.ZERO;
    var calldata = [_]core.Felt{public_key_x};
    return calculateContractAddress(
        effective_salt,
        class_hash,
        &calldata,
        core.Felt.ZERO,
    );
}

fn hashElements(elements: []const core.Felt) Error!core.Felt {
    var current = core.Felt.ZERO;
    for (elements) |el| {
        current = crypto.pedersen.hash(current, el) catch return Error.CryptoFailure;
    }

    const length_felt = core.Felt.fromU64(@intCast(elements.len));
    return crypto.pedersen.hash(current, length_felt) catch Error.CryptoFailure;
}

fn encodeShortString(s: []const u8) Error!core.Felt {
    if (s.len > 31) return Error.InvalidLength;
    return core.Felt.fromBytesBeSlice(s) catch Error.CryptoFailure;
}
