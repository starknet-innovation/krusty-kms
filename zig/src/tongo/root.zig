const std = @import("std");

pub const account = @import("account.zig");
pub const crypto = @import("crypto.zig");
pub const operations = @import("operations.zig");

pub const TongoAccount = account.TongoAccount;
pub const AccountState = account.AccountState;

pub const FundParams = operations.FundParams;
pub const TransferParams = operations.TransferParams;
pub const RolloverParams = operations.RolloverParams;
pub const WithdrawParams = operations.WithdrawParams;
pub const RagequitParams = operations.RagequitParams;

pub const FundProof = operations.FundProof;
pub const TransferProof = operations.TransferProof;
pub const RolloverProof = operations.RolloverProof;
pub const WithdrawProof = operations.WithdrawProof;
pub const RagequitProof = operations.RagequitProof;

pub const transfer = operations.transfer;
pub const rollover = operations.rollover;
pub const withdraw = operations.withdraw;
pub const ragequit = operations.ragequit;

pub fn fund(
    allocator: std.mem.Allocator,
    tongo_account: *const TongoAccount,
    params: FundParams,
) operations.Error!FundProof {
    return operations.fund(allocator, tongo_account, params);
}
