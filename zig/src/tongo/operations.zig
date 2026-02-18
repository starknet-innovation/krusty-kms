const std = @import("std");
const core = @import("../core/root.zig");
const she = @import("../she/root.zig");
const account_mod = @import("account.zig");
const tcrypto = @import("crypto.zig");

const FUND_CAIRO_STRING = core.Felt.fromHex("0x66756e64") catch unreachable;
const TRANSFER_CAIRO_STRING = core.Felt.fromHex("0x7472616e73666572") catch unreachable;
const RAGEQUIT_CAIRO_STRING = core.Felt.fromHex("0x7261676571756974") catch unreachable;
const ROLLOVER_CAIRO_STRING = core.Felt.fromHex("0x726f6c6c6f766572") catch unreachable;
const WITHDRAW_CAIRO_STRING = core.Felt.fromHex("0x7769746864726177") catch unreachable;

pub const FundParams = struct {
    amount: u128,
    nonce: core.Felt,
    chain_id: core.Felt,
    tongo_address: core.Felt,
    auditor_pub_key: ?core.ProjectivePoint = null,
    current_balance: she.types.ElGamalCiphertext,
};

pub const TransferParams = struct {
    recipient_public_key: core.ProjectivePoint,
    amount: u128,
    nonce: core.Felt,
    chain_id: core.Felt,
    tongo_address: core.Felt,
    current_balance: she.types.ElGamalCiphertext,
    bit_size: usize,
    auditor_pub_key: ?core.ProjectivePoint = null,
};

pub const RolloverParams = struct {
    nonce: core.Felt,
    chain_id: core.Felt,
    tongo_address: core.Felt,
};

pub const WithdrawParams = struct {
    recipient_address: core.Felt,
    amount: u128,
    nonce: core.Felt,
    chain_id: core.Felt,
    tongo_address: core.Felt,
    current_balance: she.types.ElGamalCiphertext,
    bit_size: usize,
    auditor_key: ?core.ProjectivePoint = null,
};

pub const RagequitParams = struct {
    recipient_address: core.Felt,
    nonce: core.Felt,
    chain_id: core.Felt,
    tongo_address: core.Felt,
    current_balance: she.types.ElGamalCiphertext,
    auditor_key: ?core.ProjectivePoint = null,
};

pub const Audit = struct {
    audited_balance: she.types.ElGamalCiphertext,
    hint_ciphertext: [64]u8,
    hint_nonce: [24]u8,
    proof: she.types.AuditProof,
};

pub const FundProof = struct {
    y: core.ProjectivePoint,
    proof: she.types.PoeProof,
    amount: u128,
    audit: ?Audit,
};

pub const ProofOfTransfer = struct {
    a_x: core.ProjectivePoint,
    a_r: core.ProjectivePoint,
    a_r2: core.ProjectivePoint,
    a_b: core.ProjectivePoint,
    a_b2: core.ProjectivePoint,
    a_v: core.ProjectivePoint,
    a_v2: core.ProjectivePoint,
    a_bar: core.ProjectivePoint,
    s_x: core.Felt,
    s_r: core.Felt,
    s_b: core.Felt,
    s_b2: core.Felt,
    s_r2: core.Felt,
    r_aux: core.ProjectivePoint,
    range: she.types.RangeProof,
    r_aux2: core.ProjectivePoint,
    range2: she.types.RangeProof,

    pub fn deinit(self: *ProofOfTransfer, allocator: std.mem.Allocator) void {
        self.range.deinit(allocator);
        self.range2.deinit(allocator);
    }
};

pub const TransferProof = struct {
    transfer_balance_l: core.ProjectivePoint,
    transfer_balance_r: core.ProjectivePoint,
    transfer_balance_self_l: core.ProjectivePoint,
    transfer_balance_self_r: core.ProjectivePoint,
    proof: ProofOfTransfer,
    new_balance_cipher: she.types.ElGamalCiphertext,
    audit_balance: ?Audit,
    audit_transfer: ?Audit,

    pub fn deinit(self: *TransferProof, allocator: std.mem.Allocator) void {
        self.proof.deinit(allocator);
    }
};

pub const RolloverProof = struct {
    y: core.ProjectivePoint,
    proof: she.types.PoeProof,
    pending_amount: u128,
};

pub const WithdrawProof = struct {
    y: core.ProjectivePoint,
    a_x: core.ProjectivePoint,
    a_r: core.ProjectivePoint,
    a: core.ProjectivePoint,
    a_v: core.ProjectivePoint,
    sx: core.Felt,
    sb: core.Felt,
    sr: core.Felt,
    r_aux: core.ProjectivePoint,
    range: she.types.RangeProof,
    amount: u128,
    recipient: core.Felt,
    audit: ?Audit,

    pub fn deinit(self: *WithdrawProof, allocator: std.mem.Allocator) void {
        self.range.deinit(allocator);
    }
};

pub const RagequitProof = struct {
    y: core.ProjectivePoint,
    a_x: core.ProjectivePoint,
    a_r: core.ProjectivePoint,
    sx: core.Felt,
    amount: u128,
    recipient: core.Felt,
    audit: ?Audit,
};

pub const Error = error{
    InvalidAmount,
    InsufficientBalance,
    PointAtInfinity,
    InvalidCiphertext,
    InvalidInput,
    CryptoFailure,
    OutOfMemory,
};

pub fn fund(
    allocator: std.mem.Allocator,
    account: *const account_mod.TongoAccount,
    params: FundParams,
) Error!FundProof {
    if (params.amount == 0) return Error.InvalidAmount;

    const y = account.keypair.public_key;
    const y_affine = y.toAffine() orelse return Error.PointAtInfinity;

    const prefix_inputs = [_]core.Felt{
        params.chain_id,
        params.tongo_address,
        FUND_CAIRO_STRING,
        y_affine.x,
        y_affine.y,
        feltFromU128(params.amount),
        params.nonce,
    };
    const prefix = she.hash.poseidonHashMany(&prefix_inputs) catch return Error.CryptoFailure;

    const poe_res = she.poe.prove(allocator, account.keypair.private_key, prefix) catch |err| switch (err) {
        error.PointAtInfinity => return Error.PointAtInfinity,
        else => return Error.CryptoFailure,
    };

    const audit_data = if (params.auditor_pub_key) |auditor_key| blk: {
        const new_balance = std.math.add(u128, account.state.balance, params.amount) catch return Error.InvalidAmount;
        const fund_cipher_l = she.curve.add(
            she.curve.mul(feltFromU128(params.amount), she.curve.GENERATOR),
            she.curve.mul(FUND_CAIRO_STRING, account.keypair.public_key),
        );
        const fund_cipher_r = she.curve.mul(FUND_CAIRO_STRING, she.curve.GENERATOR);
        const new_cipher_balance = she.types.ElGamalCiphertext{
            .l = she.curve.add(params.current_balance.l, fund_cipher_l),
            .r = she.curve.add(params.current_balance.r, fund_cipher_r),
        };

        const audit_res = she.audit.prove(
            allocator,
            account.keypair.private_key,
            new_balance,
            new_cipher_balance,
            auditor_key,
        ) catch |err| switch (err) {
            error.PointAtInfinity => return Error.PointAtInfinity,
            error.InvalidInput, error.InvalidCiphertext => return Error.InvalidInput,
            else => return Error.CryptoFailure,
        };
        const hint = tcrypto.encryptForAuditor(
            new_balance,
            account.keypair.private_key,
            auditor_key,
        ) catch |err| switch (err) {
            error.PointAtInfinity => return Error.PointAtInfinity,
            else => return Error.CryptoFailure,
        };

        break :blk Audit{
            .audited_balance = audit_res.cipher1,
            .hint_ciphertext = hint.ciphertext,
            .hint_nonce = hint.nonce,
            .proof = audit_res.proof,
        };
    } else null;

    return .{
        .y = y,
        .proof = poe_res.proof,
        .amount = params.amount,
        .audit = audit_data,
    };
}

pub fn transfer(
    allocator: std.mem.Allocator,
    account: *const account_mod.TongoAccount,
    params: TransferParams,
) Error!TransferProof {
    if (params.amount == 0) return Error.InvalidAmount;
    if (!account.hasSufficientBalance(params.amount)) return Error.InsufficientBalance;

    const x = account.keypair.private_key;
    const y = account.keypair.public_key;
    const to = params.recipient_public_key;
    const b = params.amount;
    const b0 = account.state.balance;
    const g = she.curve.GENERATOR;
    const h = she.curve.GENERATOR_H;

    const y_affine = y.toAffine() orelse return Error.PointAtInfinity;
    const to_affine = to.toAffine() orelse return Error.PointAtInfinity;

    const prefix_inputs = [_]core.Felt{
        params.chain_id,
        params.tongo_address,
        TRANSFER_CAIRO_STRING,
        y_affine.x,
        y_affine.y,
        to_affine.x,
        to_affine.y,
        params.nonce,
    };
    const prefix = she.hash.poseidonHashMany(&prefix_inputs) catch return Error.CryptoFailure;
    const b_left = b0 - b;

    var range_res = she.range.prove(allocator, b, params.bit_size, g, h, prefix) catch |err| switch (err) {
        error.InvalidInput => return Error.InvalidInput,
        error.OutOfMemory => return Error.OutOfMemory,
        else => return Error.CryptoFailure,
    };
    var range_res2 = she.range.prove(allocator, b_left, params.bit_size, g, h, prefix) catch |err| {
        range_res.range.deinit(allocator);
        return switch (err) {
            error.InvalidInput => Error.InvalidInput,
            error.OutOfMemory => Error.OutOfMemory,
            else => Error.CryptoFailure,
        };
    };

    errdefer range_res.range.deinit(allocator);
    errdefer range_res2.range.deinit(allocator);

    const r = range_res.randomness;
    const r2 = range_res2.randomness;

    const transfer_balance_self_l = she.curve.add(
        she.curve.mul(feltFromU128(b), g),
        she.curve.mul(r, y),
    );
    const transfer_balance_self_r = she.curve.mul(r, g);
    const transfer_balance_l = she.curve.add(
        she.curve.mul(feltFromU128(b), g),
        she.curve.mul(r, to),
    );
    const transfer_balance_r = she.curve.mul(r, g);

    const r_aux = she.curve.mul(r, g);
    const r_aux2 = she.curve.mul(r2, g);

    const g_point = subPoints(params.current_balance.r, transfer_balance_self_r);

    const kx = she.random.randomFelt();
    const kb = she.random.randomFelt();
    const kr = she.random.randomFelt();
    const kb2 = she.random.randomFelt();
    const kr2 = she.random.randomFelt();

    const a_x = she.curve.mul(kx, g);
    const a_r = she.curve.mul(kr, g);
    const a_r2 = she.curve.mul(kr2, g);
    const a_b = she.curve.add(she.curve.mul(kb, g), she.curve.mul(kr, y));
    const a_bar = she.curve.add(she.curve.mul(kb, g), she.curve.mul(kr, to));
    const a_v = she.curve.add(she.curve.mul(kb, g), she.curve.mul(kr, h));
    const a_b2 = she.curve.add(she.curve.mul(kb2, g), she.curve.mul(kx, g_point));
    const a_v2 = she.curve.add(she.curve.mul(kb2, g), she.curve.mul(kr2, h));

    const challenge = she.hash.computePoseidonChallenge(
        allocator,
        prefix,
        &[_]core.ProjectivePoint{ a_x, a_r, a_r2, a_b, a_b2, a_v, a_v2, a_bar },
    ) catch |err| switch (err) {
        error.PointAtInfinity => return Error.PointAtInfinity,
        else => return Error.CryptoFailure,
    };

    const s_x = she.scalar.scalarAdd(kx, she.scalar.scalarMul(challenge, x));
    const s_b = she.scalar.scalarAdd(kb, she.scalar.scalarMul(challenge, feltFromU128(b)));
    const s_r = she.scalar.scalarAdd(kr, she.scalar.scalarMul(challenge, r));
    const s_b2 = she.scalar.scalarAdd(kb2, she.scalar.scalarMul(challenge, feltFromU128(b_left)));
    const s_r2 = she.scalar.scalarAdd(kr2, she.scalar.scalarMul(challenge, r2));

    const proof = ProofOfTransfer{
        .a_x = a_x,
        .a_r = a_r,
        .a_r2 = a_r2,
        .a_b = a_b,
        .a_b2 = a_b2,
        .a_v = a_v,
        .a_v2 = a_v2,
        .a_bar = a_bar,
        .s_x = s_x,
        .s_r = s_r,
        .s_b = s_b,
        .s_b2 = s_b2,
        .s_r2 = s_r2,
        .r_aux = r_aux,
        .range = range_res.range,
        .r_aux2 = r_aux2,
        .range2 = range_res2.range,
    };

    const new_balance_cipher = she.types.ElGamalCiphertext{
        .l = subPoints(params.current_balance.l, transfer_balance_self_l),
        .r = subPoints(params.current_balance.r, transfer_balance_self_r),
    };

    var audit_balance: ?Audit = null;
    var audit_transfer: ?Audit = null;
    if (params.auditor_pub_key) |auditor_key| {
        const audit_balance_res = she.audit.proveWithValidation(
            allocator,
            x,
            b_left,
            new_balance_cipher,
            auditor_key,
            false,
        ) catch |err| switch (err) {
            error.PointAtInfinity => return Error.PointAtInfinity,
            error.InvalidInput, error.InvalidCiphertext => return Error.InvalidInput,
            else => return Error.CryptoFailure,
        };
        const balance_hint = tcrypto.encryptForAuditor(b_left, x, auditor_key) catch |err| switch (err) {
            error.PointAtInfinity => return Error.PointAtInfinity,
            else => return Error.CryptoFailure,
        };
        audit_balance = .{
            .audited_balance = audit_balance_res.cipher1,
            .hint_ciphertext = balance_hint.ciphertext,
            .hint_nonce = balance_hint.nonce,
            .proof = audit_balance_res.proof,
        };

        const transfer_cipher_self = she.types.ElGamalCiphertext{
            .l = transfer_balance_self_l,
            .r = transfer_balance_self_r,
        };
        const audit_transfer_res = she.audit.prove(
            allocator,
            x,
            b,
            transfer_cipher_self,
            auditor_key,
        ) catch |err| switch (err) {
            error.PointAtInfinity => return Error.PointAtInfinity,
            error.InvalidInput, error.InvalidCiphertext => return Error.InvalidInput,
            else => return Error.CryptoFailure,
        };
        const transfer_hint = tcrypto.encryptForAuditor(b, x, auditor_key) catch |err| switch (err) {
            error.PointAtInfinity => return Error.PointAtInfinity,
            else => return Error.CryptoFailure,
        };
        audit_transfer = .{
            .audited_balance = audit_transfer_res.cipher1,
            .hint_ciphertext = transfer_hint.ciphertext,
            .hint_nonce = transfer_hint.nonce,
            .proof = audit_transfer_res.proof,
        };
    }

    return .{
        .transfer_balance_l = transfer_balance_l,
        .transfer_balance_r = transfer_balance_r,
        .transfer_balance_self_l = transfer_balance_self_l,
        .transfer_balance_self_r = transfer_balance_self_r,
        .proof = proof,
        .new_balance_cipher = new_balance_cipher,
        .audit_balance = audit_balance,
        .audit_transfer = audit_transfer,
    };
}

pub fn rollover(
    allocator: std.mem.Allocator,
    account: *const account_mod.TongoAccount,
    params: RolloverParams,
) Error!RolloverProof {
    const y = account.keypair.public_key;
    const y_affine = y.toAffine() orelse return Error.PointAtInfinity;

    const prefix_inputs = [_]core.Felt{
        params.chain_id,
        params.tongo_address,
        ROLLOVER_CAIRO_STRING,
        y_affine.x,
        y_affine.y,
        params.nonce,
    };
    const prefix = she.hash.poseidonHashMany(&prefix_inputs) catch return Error.CryptoFailure;
    const poe_res = she.poe.prove(allocator, account.keypair.private_key, prefix) catch |err| switch (err) {
        error.PointAtInfinity => return Error.PointAtInfinity,
        else => return Error.CryptoFailure,
    };

    return .{
        .y = y,
        .proof = poe_res.proof,
        .pending_amount = account.state.pending_balance,
    };
}

pub fn withdraw(
    allocator: std.mem.Allocator,
    account: *const account_mod.TongoAccount,
    params: WithdrawParams,
) Error!WithdrawProof {
    if (params.amount == 0) return Error.InvalidAmount;
    if (!account.hasSufficientBalance(params.amount)) return Error.InsufficientBalance;

    const x = account.keypair.private_key;
    const g = she.curve.GENERATOR;
    const h = she.curve.GENERATOR_H;
    const y = account.keypair.public_key;
    const y_affine = y.toAffine() orelse return Error.PointAtInfinity;

    const l0 = params.current_balance.l;
    const r0 = params.current_balance.r;

    const g_b = subPoints(l0, she.curve.mul(x, r0));
    const expected_g_b = she.curve.mul(feltFromU128(account.state.balance), g);
    if (!she.curve.pointEq(g_b, expected_g_b)) return Error.InvalidCiphertext;

    const prefix_inputs = [_]core.Felt{
        params.chain_id,
        params.tongo_address,
        WITHDRAW_CAIRO_STRING,
        y_affine.x,
        y_affine.y,
        params.nonce,
        feltFromU128(params.amount),
        params.recipient_address,
    };
    const prefix = she.hash.poseidonHashMany(&prefix_inputs) catch return Error.CryptoFailure;
    const left = account.state.balance - params.amount;

    var range_res = she.range.prove(allocator, left, params.bit_size, g, h, prefix) catch |err| switch (err) {
        error.InvalidInput => return Error.InvalidInput,
        error.OutOfMemory => return Error.OutOfMemory,
        else => return Error.CryptoFailure,
    };
    errdefer range_res.range.deinit(allocator);
    const r = range_res.randomness;
    const r_aux = she.curve.mul(r, g);

    const kb = she.random.randomFelt();
    const kx = she.random.randomFelt();
    const kr = she.random.randomFelt();

    const a_x = she.curve.mul(kx, g);
    const a_r = she.curve.mul(kr, g);
    const g_kb = she.curve.mul(kb, g);
    const r0_kx = she.curve.mul(kx, r0);
    const h_kr = she.curve.mul(kr, h);

    const a = she.curve.add(g_kb, r0_kx);
    const a_v = she.curve.add(g_kb, h_kr);

    const c = she.hash.computePoseidonChallenge(
        allocator,
        prefix,
        &[_]core.ProjectivePoint{ a_x, a_r, a, a_v },
    ) catch |err| switch (err) {
        error.PointAtInfinity => return Error.PointAtInfinity,
        else => return Error.CryptoFailure,
    };

    const sb = she.scalar.scalarAdd(kb, she.scalar.scalarMul(c, feltFromU128(left)));
    const sx = she.scalar.scalarAdd(kx, she.scalar.scalarMul(c, x));
    const sr = she.scalar.scalarAdd(kr, she.scalar.scalarMul(c, r));

    const audit_data = if (params.auditor_key) |auditor_key| blk: {
        const cipher_l = she.curve.add(
            she.curve.mul(feltFromU128(params.amount), g),
            she.curve.mul(WITHDRAW_CAIRO_STRING, y),
        );
        const cipher_r = she.curve.mul(WITHDRAW_CAIRO_STRING, g);
        const leftover_cipher = she.types.ElGamalCiphertext{
            .l = subPoints(l0, cipher_l),
            .r = subPoints(r0, cipher_r),
        };

        const audit_res = she.audit.proveWithValidation(
            allocator,
            x,
            left,
            leftover_cipher,
            auditor_key,
            false,
        ) catch |err| switch (err) {
            error.PointAtInfinity => return Error.PointAtInfinity,
            error.InvalidInput, error.InvalidCiphertext => return Error.InvalidInput,
            else => return Error.CryptoFailure,
        };
        const hint = tcrypto.encryptForAuditor(left, x, auditor_key) catch |err| switch (err) {
            error.PointAtInfinity => return Error.PointAtInfinity,
            else => return Error.CryptoFailure,
        };
        break :blk Audit{
            .audited_balance = audit_res.cipher1,
            .hint_ciphertext = hint.ciphertext,
            .hint_nonce = hint.nonce,
            .proof = audit_res.proof,
        };
    } else null;

    return .{
        .y = y,
        .a_x = a_x,
        .a_r = a_r,
        .a = a,
        .a_v = a_v,
        .sx = sx,
        .sb = sb,
        .sr = sr,
        .r_aux = r_aux,
        .range = range_res.range,
        .amount = params.amount,
        .recipient = params.recipient_address,
        .audit = audit_data,
    };
}

pub fn ragequit(
    allocator: std.mem.Allocator,
    account: *const account_mod.TongoAccount,
    params: RagequitParams,
) Error!RagequitProof {
    const x = account.keypair.private_key;
    const g = she.curve.GENERATOR;
    const y = account.keypair.public_key;
    const y_affine = y.toAffine() orelse return Error.PointAtInfinity;

    const l0 = params.current_balance.l;
    const r0 = params.current_balance.r;

    const g_b = subPoints(l0, she.curve.mul(x, r0));
    const expected = she.curve.mul(feltFromU128(account.state.balance), g);
    if (!she.curve.pointEq(g_b, expected)) return Error.InvalidCiphertext;

    const full_amount = account.state.balance;
    const prefix_inputs = [_]core.Felt{
        params.chain_id,
        params.tongo_address,
        RAGEQUIT_CAIRO_STRING,
        y_affine.x,
        y_affine.y,
        params.nonce,
        feltFromU128(full_amount),
        params.recipient_address,
    };
    const prefix = she.hash.poseidonHashMany(&prefix_inputs) catch return Error.CryptoFailure;

    const kx = she.random.randomFelt();
    const a_x = she.curve.mul(kx, g);
    const a_r = she.curve.mul(kx, r0);
    const c = she.hash.computePoseidonChallenge(
        allocator,
        prefix,
        &[_]core.ProjectivePoint{ a_x, a_r },
    ) catch |err| switch (err) {
        error.PointAtInfinity => return Error.PointAtInfinity,
        else => return Error.CryptoFailure,
    };
    const sx = she.scalar.scalarAdd(kx, she.scalar.scalarMul(c, x));

    const audit_data = if (params.auditor_key) |auditor_key| blk: {
        const new_balance_cipher = she.types.ElGamalCiphertext{
            .l = y,
            .r = g,
        };
        const audit_res = she.audit.proveWithValidation(
            allocator,
            x,
            0,
            new_balance_cipher,
            auditor_key,
            false,
        ) catch |err| switch (err) {
            error.PointAtInfinity => return Error.PointAtInfinity,
            error.InvalidInput, error.InvalidCiphertext => return Error.InvalidInput,
            else => return Error.CryptoFailure,
        };
        const hint = tcrypto.encryptForAuditor(0, x, auditor_key) catch |err| switch (err) {
            error.PointAtInfinity => return Error.PointAtInfinity,
            else => return Error.CryptoFailure,
        };
        break :blk Audit{
            .audited_balance = audit_res.cipher1,
            .hint_ciphertext = hint.ciphertext,
            .hint_nonce = hint.nonce,
            .proof = audit_res.proof,
        };
    } else null;

    return .{
        .y = y,
        .a_x = a_x,
        .a_r = a_r,
        .sx = sx,
        .amount = full_amount,
        .recipient = params.recipient_address,
        .audit = audit_data,
    };
}

fn feltFromU128(value: u128) core.Felt {
    return core.Felt.fromInt(@as(u256, value)) catch unreachable;
}

fn subPoints(a: core.ProjectivePoint, b: core.ProjectivePoint) core.ProjectivePoint {
    return she.curve.add(a, she.curve.neg(b));
}
