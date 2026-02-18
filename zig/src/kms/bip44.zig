const std = @import("std");

pub const Error = error{
    InvalidPath,
    InvalidSegment,
    HardenedRequired,
    HardenedForbidden,
};

pub const TONGO_COIN_TYPE: u32 = 5454;
pub const STARKNET_COIN_TYPE: u32 = 9004;
pub const TONGO_VIEW_COIN_TYPE: u32 = 5353;
pub const NOSTR_COIN_TYPE: u32 = 1237;

pub const Bip44Path = struct {
    purpose: u32,
    coin_type: u32,
    account: u32,
    change: u32,
    address_index: u32,

    pub fn tongo(index: u32) Bip44Path {
        return .{
            .purpose = 44,
            .coin_type = TONGO_COIN_TYPE,
            .account = 0,
            .change = 0,
            .address_index = index,
        };
    }

    pub fn parse(path: []const u8) Error!Bip44Path {
        var it = std.mem.splitScalar(u8, path, '/');

        const root = it.next() orelse return Error.InvalidPath;
        if (!std.mem.eql(u8, root, "m")) return Error.InvalidPath;

        const purpose_seg = it.next() orelse return Error.InvalidPath;
        const coin_seg = it.next() orelse return Error.InvalidPath;
        const account_seg = it.next() orelse return Error.InvalidPath;
        const change_seg = it.next() orelse return Error.InvalidPath;
        const index_seg = it.next() orelse return Error.InvalidPath;
        if (it.next() != null) return Error.InvalidPath;

        const purpose = try parseSegment(purpose_seg, true);
        const coin_type = try parseSegment(coin_seg, true);
        const account = try parseSegment(account_seg, true);
        const change = try parseSegment(change_seg, false);
        const address_index = try parseSegment(index_seg, false);

        return .{
            .purpose = purpose,
            .coin_type = coin_type,
            .account = account,
            .change = change,
            .address_index = address_index,
        };
    }

    pub fn format(self: Bip44Path, writer: anytype) !void {
        try writer.print(
            "m/{d}'/{d}'/{d}'/{d}/{d}",
            .{
                self.purpose,
                self.coin_type,
                self.account,
                self.change,
                self.address_index,
            },
        );
    }
};

fn parseSegment(segment: []const u8, expect_hardened: bool) Error!u32 {
    if (segment.len == 0) return Error.InvalidSegment;

    const hardened = std.mem.endsWith(u8, segment, "'");
    if (expect_hardened and !hardened) return Error.HardenedRequired;
    if (!expect_hardened and hardened) return Error.HardenedForbidden;

    const digits = if (hardened) segment[0 .. segment.len - 1] else segment;
    if (digits.len == 0) return Error.InvalidSegment;

    return std.fmt.parseUnsigned(u32, digits, 10) catch Error.InvalidSegment;
}
