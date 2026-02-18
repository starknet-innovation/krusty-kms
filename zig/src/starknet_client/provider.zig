const std = @import("std");

pub const Provider = struct {
    rpc_url: []const u8,

    pub fn deinit(self: *Provider, allocator: std.mem.Allocator) void {
        allocator.free(self.rpc_url);
        self.* = .{ .rpc_url = &.{} };
    }
};

pub const Error = error{
    InvalidUrl,
    OutOfMemory,
    HttpFailure,
};

/// Creates a provider config from a Starknet JSON-RPC URL.
/// Network I/O is intentionally kept outside this core module.
pub fn createProvider(
    allocator: std.mem.Allocator,
    rpc_url: []const u8,
) Error!Provider {
    const parsed = std.Uri.parse(rpc_url) catch return Error.InvalidUrl;
    if (parsed.scheme.len == 0 or parsed.host == null) return Error.InvalidUrl;

    const owned = allocator.dupe(u8, rpc_url) catch return Error.OutOfMemory;
    return .{ .rpc_url = owned };
}

/// Performs a raw JSON-RPC call and returns the response body bytes.
/// `params_json` must be a valid JSON array/object fragment.
pub fn callRaw(
    allocator: std.mem.Allocator,
    provider: Provider,
    method: []const u8,
    params_json: []const u8,
    id: u64,
) Error![]u8 {
    const uri = std.Uri.parse(provider.rpc_url) catch return Error.InvalidUrl;
    const body = std.fmt.allocPrint(
        allocator,
        "{{\"jsonrpc\":\"2.0\",\"id\":{d},\"method\":\"{s}\",\"params\":{s}}}",
        .{ id, method, params_json },
    ) catch return Error.OutOfMemory;
    defer allocator.free(body);

    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    var server_header_buffer: [16 * 1024]u8 = undefined;
    var req = client.open(.POST, uri, .{
        .server_header_buffer = &server_header_buffer,
        .extra_headers = &.{
            .{ .name = "content-type", .value = "application/json" },
        },
    }) catch return Error.HttpFailure;
    defer req.deinit();

    req.send() catch return Error.HttpFailure;
    req.writer().writeAll(body) catch return Error.HttpFailure;
    req.finish() catch return Error.HttpFailure;
    req.wait() catch return Error.HttpFailure;
    return req.reader().readAllAlloc(allocator, 4 * 1024 * 1024) catch return Error.HttpFailure;
}
