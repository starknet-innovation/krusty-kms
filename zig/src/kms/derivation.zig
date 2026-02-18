const core = @import("../core/root.zig");
const bip44 = @import("bip44.zig");
const bip39 = @import("mnemonic.zig");
const bip32 = @import("bip32.zig");
const grinding = @import("grinding.zig");

pub const Error = error{
    InvalidMnemonic,
    CryptoFailure,
};

pub const TongoKeyPair = struct {
    private_key: core.Felt,
    public_key: core.ProjectivePoint,
};

pub const NostrKeyPair = struct {
    private_key: [32]u8,
    public_key_xonly: [32]u8,
};

pub fn derivePrivateKeyWithCoinType(
    mnemonic: []const u8,
    index: u32,
    account_index: u32,
    coin_type: u32,
    passphrase: []const u8,
) Error!core.Felt {
    const seed = bip39.mnemonicToSeed(mnemonic, passphrase) catch |err| switch (err) {
        error.InvalidMnemonic => return Error.InvalidMnemonic,
        else => return Error.CryptoFailure,
    };

    const master = bip32.deriveMasterKey(&seed);
    const path = [_]u32{
        44 | 0x8000_0000,
        coin_type | 0x8000_0000,
        account_index | 0x8000_0000,
        0,
        index,
    };
    const node = bip32.derivePath(master, &path) catch return Error.CryptoFailure;
    return grinding.grindKey(node.key) catch Error.CryptoFailure;
}

pub fn deriveKeypairWithCoinType(
    mnemonic: []const u8,
    index: u32,
    account_index: u32,
    coin_type: u32,
    passphrase: []const u8,
) Error!TongoKeyPair {
    const private_key = try derivePrivateKeyWithCoinType(
        mnemonic,
        index,
        account_index,
        coin_type,
        passphrase,
    );

    if (private_key.isZero()) return Error.CryptoFailure;
    const public_key = core.ProjectivePoint.scalarMulSecretCt(core.ProjectivePoint.generator(), private_key);
    return .{
        .private_key = private_key,
        .public_key = public_key,
    };
}

pub fn deriveViewPrivateKey(
    mnemonic: []const u8,
    index: u32,
    account_index: u32,
    passphrase: []const u8,
) Error!core.Felt {
    return derivePrivateKeyWithCoinType(
        mnemonic,
        index,
        account_index,
        bip44.TONGO_VIEW_COIN_TYPE,
        passphrase,
    );
}

pub fn deriveViewKeypair(
    mnemonic: []const u8,
    index: u32,
    account_index: u32,
    passphrase: []const u8,
) Error!TongoKeyPair {
    return deriveKeypairWithCoinType(
        mnemonic,
        index,
        account_index,
        bip44.TONGO_VIEW_COIN_TYPE,
        passphrase,
    );
}

pub fn deriveNostrPrivateKey(
    mnemonic: []const u8,
    index: u32,
    account_index: u32,
    passphrase: []const u8,
) Error![32]u8 {
    const seed = bip39.mnemonicToSeed(mnemonic, passphrase) catch |err| switch (err) {
        error.InvalidMnemonic => return Error.InvalidMnemonic,
        else => return Error.CryptoFailure,
    };

    const master = bip32.deriveMasterKey(&seed);
    const path = [_]u32{
        44 | 0x8000_0000,
        bip44.NOSTR_COIN_TYPE | 0x8000_0000,
        account_index | 0x8000_0000,
        0,
        index,
    };
    const node = bip32.derivePath(master, &path) catch return Error.CryptoFailure;
    return node.key;
}

pub fn deriveNostrKeypair(
    mnemonic: []const u8,
    index: u32,
    account_index: u32,
    passphrase: []const u8,
) Error!NostrKeyPair {
    const private_key = try deriveNostrPrivateKey(mnemonic, index, account_index, passphrase);
    const public_key_xonly = bip32.secpXOnlyPublicKey(private_key) catch return Error.CryptoFailure;
    return .{
        .private_key = private_key,
        .public_key_xonly = public_key_xonly,
    };
}
