const std = @import("std");
const core = @import("../core/root.zig");
const tongo = @import("../tongo/root.zig");
const serialization = @import("serialization.zig");
const selectors = @import("selectors.zig");

pub const Call = struct {
    to: core.Felt,
    selector: core.Felt,
    calldata: []core.Felt,

    pub fn deinit(self: *Call, allocator: std.mem.Allocator) void {
        allocator.free(self.calldata);
        self.* = .{
            .to = core.Felt.ZERO,
            .selector = core.Felt.ZERO,
            .calldata = &.{},
        };
    }
};

pub const FundCalls = struct {
    approve_call: Call,
    fund_call: Call,

    pub fn deinit(self: *FundCalls, allocator: std.mem.Allocator) void {
        self.approve_call.deinit(allocator);
        self.fund_call.deinit(allocator);
    }
};

pub const Error = error{
    InvalidInput,
    OutOfMemory,
    Overflow,
    InvalidPoint,
};

pub fn buildFundCalls(
    allocator: std.mem.Allocator,
    tongo_address: core.Felt,
    erc20_address: core.Felt,
    rate: u128,
    proof: tongo.FundProof,
    hint_ciphertext: [64]u8,
    hint_nonce: [24]u8,
) Error!FundCalls {
    const approve_amount = std.math.mul(u128, proof.amount, rate) catch return Error.Overflow;
    var approve = try buildErc20Approve(allocator, erc20_address, tongo_address, approve_amount);
    errdefer approve.deinit(allocator);

    var calldata: std.ArrayList(core.Felt) = .empty;
    defer calldata.deinit(allocator);

    const to = serialization.serializeProjectivePoint(proof.y) catch return Error.InvalidPoint;
    calldata.append(allocator, to[0]) catch return Error.OutOfMemory;
    calldata.append(allocator, to[1]) catch return Error.OutOfMemory;

    calldata.append(allocator, feltFromU128(proof.amount)) catch return Error.OutOfMemory;

    const hint = serialization.serializeAeBalance(hint_ciphertext, hint_nonce);
    for (hint) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;

    const poe = serialization.serializePoeProof(proof.proof) catch return Error.InvalidInput;
    for (poe) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;

    if (proof.audit) |audit| {
        calldata.append(allocator, core.Felt.ZERO) catch return Error.OutOfMemory;
        const balance = serialization.serializeCipherBalance(audit.audited_balance) catch return Error.InvalidPoint;
        for (balance) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;

        const audit_hint = serialization.serializeAeBalance(audit.hint_ciphertext, audit.hint_nonce);
        for (audit_hint) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;

        const audit_proof = serialization.serializeAuditProof(audit.proof) catch return Error.InvalidPoint;
        for (audit_proof) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;
    } else {
        calldata.append(allocator, core.Felt.ONE) catch return Error.OutOfMemory;
    }

    const fund_call = Call{
        .to = tongo_address,
        .selector = selectors.selectorFromName("fund"),
        .calldata = calldata.toOwnedSlice(allocator) catch return Error.OutOfMemory,
    };

    return .{
        .approve_call = approve,
        .fund_call = fund_call,
    };
}

pub fn buildErc20Approve(
    allocator: std.mem.Allocator,
    erc20_address: core.Felt,
    spender: core.Felt,
    amount: u128,
) Error!Call {
    const amount_u256 = serialization.u128ToU256(amount);
    const calldata = allocator.alloc(core.Felt, 3) catch return Error.OutOfMemory;
    calldata[0] = spender;
    calldata[1] = amount_u256[0];
    calldata[2] = amount_u256[1];

    return .{
        .to = erc20_address,
        .selector = selectors.selectorFromName("approve"),
        .calldata = calldata,
    };
}

pub fn buildRolloverCall(
    allocator: std.mem.Allocator,
    tongo_address: core.Felt,
    proof: tongo.RolloverProof,
    hint_ciphertext: [64]u8,
    hint_nonce: [24]u8,
) Error!Call {
    var calldata: std.ArrayList(core.Felt) = .empty;
    defer calldata.deinit(allocator);

    const to = serialization.serializeProjectivePoint(proof.y) catch return Error.InvalidPoint;
    calldata.append(allocator, to[0]) catch return Error.OutOfMemory;
    calldata.append(allocator, to[1]) catch return Error.OutOfMemory;

    const hint = serialization.serializeAeBalance(hint_ciphertext, hint_nonce);
    for (hint) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;

    const poe = serialization.serializePoeProof(proof.proof) catch return Error.InvalidInput;
    for (poe) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;

    return .{
        .to = tongo_address,
        .selector = selectors.selectorFromName("rollover"),
        .calldata = calldata.toOwnedSlice(allocator) catch return Error.OutOfMemory,
    };
}

pub fn buildWithdrawCall(
    allocator: std.mem.Allocator,
    tongo_address: core.Felt,
    proof: tongo.WithdrawProof,
    hint_ciphertext: [64]u8,
    hint_nonce: [24]u8,
) Error!Call {
    var calldata: std.ArrayList(core.Felt) = .empty;
    defer calldata.deinit(allocator);

    const from = serialization.serializeProjectivePoint(proof.y) catch return Error.InvalidPoint;
    calldata.append(allocator, from[0]) catch return Error.OutOfMemory;
    calldata.append(allocator, from[1]) catch return Error.OutOfMemory;

    calldata.append(allocator, proof.recipient) catch return Error.OutOfMemory;
    calldata.append(allocator, feltFromU128(proof.amount)) catch return Error.OutOfMemory;

    const hint = serialization.serializeAeBalance(hint_ciphertext, hint_nonce);
    for (hint) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;

    const ax = serialization.serializeProjectivePoint(proof.a_x) catch return Error.InvalidPoint;
    const ar = serialization.serializeProjectivePoint(proof.a_r) catch return Error.InvalidPoint;
    const a = serialization.serializeProjectivePoint(proof.a) catch return Error.InvalidPoint;
    const av = serialization.serializeProjectivePoint(proof.a_v) catch return Error.InvalidPoint;
    for ([_][2]core.Felt{ ax, ar, a, av }) |pair| {
        calldata.append(allocator, pair[0]) catch return Error.OutOfMemory;
        calldata.append(allocator, pair[1]) catch return Error.OutOfMemory;
    }

    calldata.append(allocator, proof.sx) catch return Error.OutOfMemory;
    calldata.append(allocator, proof.sb) catch return Error.OutOfMemory;
    calldata.append(allocator, proof.sr) catch return Error.OutOfMemory;

    const r_aux = serialization.serializeProjectivePoint(proof.r_aux) catch return Error.InvalidPoint;
    calldata.append(allocator, r_aux[0]) catch return Error.OutOfMemory;
    calldata.append(allocator, r_aux[1]) catch return Error.OutOfMemory;

    const range = serialization.serializeRange(allocator, proof.range) catch |err| switch (err) {
        error.OutOfMemory => return Error.OutOfMemory,
        else => return Error.InvalidInput,
    };
    defer allocator.free(range);
    for (range) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;

    if (proof.audit) |audit| {
        calldata.append(allocator, core.Felt.ZERO) catch return Error.OutOfMemory;
        const balance = serialization.serializeCipherBalance(audit.audited_balance) catch return Error.InvalidPoint;
        for (balance) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;
        const audit_hint = serialization.serializeAeBalance(audit.hint_ciphertext, audit.hint_nonce);
        for (audit_hint) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;
        const audit_proof = serialization.serializeAuditProof(audit.proof) catch return Error.InvalidPoint;
        for (audit_proof) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;
    } else {
        calldata.append(allocator, core.Felt.ONE) catch return Error.OutOfMemory;
    }

    return .{
        .to = tongo_address,
        .selector = selectors.selectorFromName("withdraw"),
        .calldata = calldata.toOwnedSlice(allocator) catch return Error.OutOfMemory,
    };
}

pub fn buildTransferCall(
    allocator: std.mem.Allocator,
    tongo_address: core.Felt,
    from: core.ProjectivePoint,
    to: core.ProjectivePoint,
    proof: tongo.TransferProof,
    hint_transfer_ciphertext: [64]u8,
    hint_transfer_nonce: [24]u8,
    hint_leftover_ciphertext: [64]u8,
    hint_leftover_nonce: [24]u8,
) Error!Call {
    var calldata: std.ArrayList(core.Felt) = .empty;
    defer calldata.deinit(allocator);

    const from_ser = serialization.serializeProjectivePoint(from) catch return Error.InvalidPoint;
    calldata.append(allocator, from_ser[0]) catch return Error.OutOfMemory;
    calldata.append(allocator, from_ser[1]) catch return Error.OutOfMemory;

    const to_ser = serialization.serializeProjectivePoint(to) catch return Error.InvalidPoint;
    calldata.append(allocator, to_ser[0]) catch return Error.OutOfMemory;
    calldata.append(allocator, to_ser[1]) catch return Error.OutOfMemory;

    const transfer_balance = serialization.serializeCipherBalance(.{
        .l = proof.transfer_balance_l,
        .r = proof.transfer_balance_r,
    }) catch return Error.InvalidPoint;
    for (transfer_balance) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;

    const transfer_balance_self = serialization.serializeCipherBalance(.{
        .l = proof.transfer_balance_self_l,
        .r = proof.transfer_balance_self_r,
    }) catch return Error.InvalidPoint;
    for (transfer_balance_self) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;

    const transfer_hint = serialization.serializeAeBalance(hint_transfer_ciphertext, hint_transfer_nonce);
    for (transfer_hint) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;

    const leftover_hint = serialization.serializeAeBalance(hint_leftover_ciphertext, hint_leftover_nonce);
    for (leftover_hint) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;

    const transfer_proof = serialization.serializeProofOfTransfer(allocator, proof.proof) catch |err| switch (err) {
        error.OutOfMemory => return Error.OutOfMemory,
        else => return Error.InvalidInput,
    };
    defer allocator.free(transfer_proof);
    for (transfer_proof) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;

    if (proof.audit_balance) |audit| {
        calldata.append(allocator, core.Felt.ZERO) catch return Error.OutOfMemory;
        const balance = serialization.serializeCipherBalance(audit.audited_balance) catch return Error.InvalidPoint;
        for (balance) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;
        const audit_hint = serialization.serializeAeBalance(audit.hint_ciphertext, audit.hint_nonce);
        for (audit_hint) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;
        const audit_proof = serialization.serializeAuditProof(audit.proof) catch return Error.InvalidPoint;
        for (audit_proof) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;
    } else {
        calldata.append(allocator, core.Felt.ONE) catch return Error.OutOfMemory;
    }

    if (proof.audit_transfer) |audit| {
        calldata.append(allocator, core.Felt.ZERO) catch return Error.OutOfMemory;
        const balance = serialization.serializeCipherBalance(audit.audited_balance) catch return Error.InvalidPoint;
        for (balance) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;
        const audit_hint = serialization.serializeAeBalance(audit.hint_ciphertext, audit.hint_nonce);
        for (audit_hint) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;
        const audit_proof = serialization.serializeAuditProof(audit.proof) catch return Error.InvalidPoint;
        for (audit_proof) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;
    } else {
        calldata.append(allocator, core.Felt.ONE) catch return Error.OutOfMemory;
    }

    return .{
        .to = tongo_address,
        .selector = selectors.selectorFromName("transfer"),
        .calldata = calldata.toOwnedSlice(allocator) catch return Error.OutOfMemory,
    };
}

pub fn buildRagequitCall(
    allocator: std.mem.Allocator,
    tongo_address: core.Felt,
    proof: tongo.RagequitProof,
    hint_ciphertext: [64]u8,
    hint_nonce: [24]u8,
) Error!Call {
    var calldata: std.ArrayList(core.Felt) = .empty;
    defer calldata.deinit(allocator);

    const from = serialization.serializeProjectivePoint(proof.y) catch return Error.InvalidPoint;
    calldata.append(allocator, from[0]) catch return Error.OutOfMemory;
    calldata.append(allocator, from[1]) catch return Error.OutOfMemory;
    calldata.append(allocator, proof.recipient) catch return Error.OutOfMemory;
    calldata.append(allocator, feltFromU128(proof.amount)) catch return Error.OutOfMemory;

    const hint = serialization.serializeAeBalance(hint_ciphertext, hint_nonce);
    for (hint) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;

    const ax = serialization.serializeProjectivePoint(proof.a_x) catch return Error.InvalidPoint;
    const ar = serialization.serializeProjectivePoint(proof.a_r) catch return Error.InvalidPoint;
    calldata.append(allocator, ax[0]) catch return Error.OutOfMemory;
    calldata.append(allocator, ax[1]) catch return Error.OutOfMemory;
    calldata.append(allocator, ar[0]) catch return Error.OutOfMemory;
    calldata.append(allocator, ar[1]) catch return Error.OutOfMemory;
    calldata.append(allocator, proof.sx) catch return Error.OutOfMemory;

    if (proof.audit) |audit| {
        calldata.append(allocator, core.Felt.ZERO) catch return Error.OutOfMemory;
        const balance = serialization.serializeCipherBalance(audit.audited_balance) catch return Error.InvalidPoint;
        for (balance) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;
        const audit_hint = serialization.serializeAeBalance(audit.hint_ciphertext, audit.hint_nonce);
        for (audit_hint) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;
        const audit_proof = serialization.serializeAuditProof(audit.proof) catch return Error.InvalidPoint;
        for (audit_proof) |felt| calldata.append(allocator, felt) catch return Error.OutOfMemory;
    } else {
        calldata.append(allocator, core.Felt.ONE) catch return Error.OutOfMemory;
    }

    return .{
        .to = tongo_address,
        .selector = selectors.selectorFromName("ragequit"),
        .calldata = calldata.toOwnedSlice(allocator) catch return Error.OutOfMemory,
    };
}

fn feltFromU128(value: u128) core.Felt {
    return core.Felt.fromInt(@as(u256, value)) catch unreachable;
}

