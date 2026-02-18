const std = @import("std");
const core = @import("../core/root.zig");
const kms = @import("../kms/root.zig");
const bip44 = @import("../kms/bip44.zig");
const she = @import("../she/root.zig");

pub const AccountState = struct {
    balance: u128 = 0,
    pending_balance: u128 = 0,
    nonce: u64 = 0,
};

pub const TongoAccount = struct {
    keypair: kms.derivation.TongoKeyPair,
    view_keypair: ?kms.derivation.TongoKeyPair,
    state: AccountState,
    contract_address: core.Felt,

    pub fn fromMnemonic(
        mnemonic: []const u8,
        index: u32,
        account_index: u32,
        contract_address: core.Felt,
        passphrase: ?[]const u8,
    ) Error!TongoAccount {
        const pass = passphrase orelse "";
        const keypair = kms.derivation.deriveKeypairWithCoinType(
            mnemonic,
            index,
            account_index,
            bip44.TONGO_COIN_TYPE,
            pass,
        ) catch |err| switch (err) {
            error.InvalidMnemonic => return Error.InvalidMnemonic,
            else => return Error.CryptoFailure,
        };

        const view_keypair = kms.derivation.deriveViewKeypair(
            mnemonic,
            index,
            account_index,
            pass,
        ) catch |err| switch (err) {
            error.InvalidMnemonic => return Error.InvalidMnemonic,
            else => return Error.CryptoFailure,
        };

        return .{
            .keypair = keypair,
            .view_keypair = view_keypair,
            .state = .{},
            .contract_address = contract_address,
        };
    }

    pub fn fromPrivateKey(private_key: core.Felt, contract_address: core.Felt) TongoAccount {
        return .{
            .keypair = .{
                .private_key = private_key,
                .public_key = core.ProjectivePoint.scalarMulSecretCt(core.ProjectivePoint.generator(), private_key),
            },
            .view_keypair = null,
            .state = .{},
            .contract_address = contract_address,
        };
    }

    pub fn fromKeys(
        owner_private_key: core.Felt,
        view_private_key: core.Felt,
        contract_address: core.Felt,
    ) TongoAccount {
        return .{
            .keypair = .{
                .private_key = owner_private_key,
                .public_key = core.ProjectivePoint.scalarMulSecretCt(core.ProjectivePoint.generator(), owner_private_key),
            },
            .view_keypair = .{
                .private_key = view_private_key,
                .public_key = core.ProjectivePoint.scalarMulSecretCt(core.ProjectivePoint.generator(), view_private_key),
            },
            .state = .{},
            .contract_address = contract_address,
        };
    }

    pub fn publicKeyHex(self: *const TongoAccount, allocator: std.mem.Allocator) Error![]u8 {
        const affine = self.keypair.public_key.toAffine() orelse return Error.PointAtInfinity;
        return serializePublicKeyHex(allocator, affine.x, affine.y);
    }

    pub fn ownerPublicKeyHex(self: *const TongoAccount, allocator: std.mem.Allocator) Error![]u8 {
        return self.publicKeyHex(allocator);
    }

    pub fn viewPublicKeyHex(self: *const TongoAccount, allocator: std.mem.Allocator) Error!?[]u8 {
        const kp = self.view_keypair orelse return null;
        const affine = kp.public_key.toAffine() orelse return Error.PointAtInfinity;
        return serializePublicKeyHex(allocator, affine.x, affine.y);
    }

    pub fn privateKeyHex(self: *const TongoAccount, allocator: std.mem.Allocator) Error![]u8 {
        return feltToHex(allocator, self.keypair.private_key);
    }

    pub fn hasViewKey(self: *const TongoAccount) bool {
        return self.view_keypair != null;
    }

    pub fn updateState(self: *TongoAccount, state: AccountState) void {
        self.state = state;
    }

    pub fn hasSufficientBalance(self: *const TongoAccount, amount: u128) bool {
        return self.state.balance >= amount;
    }

    pub fn totalBalance(self: *const TongoAccount) u128 {
        return self.state.balance +| self.state.pending_balance;
    }

    pub fn decryptWithView(
        self: *const TongoAccount,
        ciphertext: she.types.ElGamalCiphertext,
    ) Error!core.ProjectivePoint {
        const sk = if (self.view_keypair) |view| view.private_key else self.keypair.private_key;
        return she.elgamal.decrypt(ciphertext, sk) catch |err| switch (err) {
            error.PointAtInfinity => Error.PointAtInfinity,
            else => Error.CryptoFailure,
        };
    }
};

pub const Error = error{
    InvalidMnemonic,
    PointAtInfinity,
    CryptoFailure,
    OutOfMemory,
};

fn serializePublicKeyHex(
    allocator: std.mem.Allocator,
    x: core.Felt,
    y: core.Felt,
) Error![]u8 {
    const out = allocator.alloc(u8, 130) catch return Error.OutOfMemory;
    out[0] = '0';
    out[1] = 'x';

    appendHex(out[2..66], x.toBytesBe());
    appendHex(out[66..130], y.toBytesBe());
    return out;
}

fn feltToHex(allocator: std.mem.Allocator, felt: core.Felt) Error![]u8 {
    const out = allocator.alloc(u8, 66) catch return Error.OutOfMemory;
    out[0] = '0';
    out[1] = 'x';
    appendHex(out[2..66], felt.toBytesBe());
    return out;
}

fn appendHex(dst: []u8, src: [32]u8) void {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const b = src[i];
        dst[i * 2] = nibbleToHex((b >> 4) & 0x0f);
        dst[i * 2 + 1] = nibbleToHex(b & 0x0f);
    }
}

fn nibbleToHex(n: u8) u8 {
    return if (n < 10) '0' + n else 'a' + (n - 10);
}
