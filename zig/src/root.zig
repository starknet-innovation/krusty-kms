pub const core = @import("core/root.zig");
pub const crypto = @import("crypto/root.zig");
pub const kms = @import("kms/root.zig");
pub const she = @import("she/root.zig");
pub const tongo = @import("tongo/root.zig");
pub const nostr = @import("nostr/root.zig");
pub const starknet_client = @import("starknet_client/root.zig");
pub const ffi = @import("ffi/root.zig");

comptime {
    // Force inclusion of the C ABI export unit in library artifacts.
    _ = @import("ffi/exports.zig");
}

test "module graph compiles" {
    _ = core;
    _ = crypto;
    _ = kms;
    _ = she;
    _ = tongo;
    _ = nostr;
    _ = starknet_client;
    _ = ffi;
}
